#include "starks.hpp"
#include "fri/fri_pcs.hpp"  // Must come after starks.hpp for proper include ordering
#include <fstream>

void calculateWitnessSTD(SetupCtx& setupCtx, StepsParams& params, ExpressionsCtx &expressionsCtx, bool prod) {
    std::string name = prod ? "gprod_col" : "gsum_col";
    if(setupCtx.expressionsBin.getNumberHintIdsByName(name) == 0) return;
    uint64_t hint[1];
    setupCtx.expressionsBin.getHintIdsByName(hint, name);

    uint64_t nImHints = setupCtx.expressionsBin.getNumberHintIdsByName("im_col");
    uint64_t nImHintsAirVals = setupCtx.expressionsBin.getNumberHintIdsByName("im_airval");
    uint64_t nImTotalHints = nImHints + nImHintsAirVals;
    if(nImTotalHints > 0) {
        uint64_t imHints[nImHints + nImHintsAirVals];
        setupCtx.expressionsBin.getHintIdsByName(imHints, "im_col");
        setupCtx.expressionsBin.getHintIdsByName(&imHints[nImHints], "im_airval");
        std::string hintFieldDest[nImTotalHints];
        std::string hintField1[nImTotalHints];
        std::string hintField2[nImTotalHints];
        HintFieldOptions hintOptions1[nImTotalHints];
        HintFieldOptions hintOptions2[nImTotalHints];
        for(uint64_t i = 0; i < nImTotalHints; i++) {
            hintFieldDest[i] = "reference";
            hintField1[i] = "numerator";
            hintField2[i] = "denominator";
            HintFieldOptions options1;
            HintFieldOptions options2;
            options2.inverse = true;
            hintOptions1[i] = options1;
            hintOptions2[i] = options2;
        }

        multiplyHintFields(setupCtx, params, expressionsCtx, nImTotalHints, imHints, hintFieldDest, hintField1, hintField2, hintOptions1, hintOptions2);
        
    }

    HintFieldOptions options1;
    HintFieldOptions options2;
    options2.inverse = true;

    std::string hintFieldNameAirgroupVal = setupCtx.starkInfo.airgroupValuesMap.size() > 0 ? "result" : "";

    accMulHintFields(setupCtx, params, expressionsCtx, hint[0], "reference", hintFieldNameAirgroupVal, "numerator_air", "denominator_air", options1, options2, !prod);
    updateAirgroupValue(setupCtx, params, hint[0], hintFieldNameAirgroupVal, "numerator_direct", "denominator_direct", options1, options2, !prod);
}

void genProof(SetupCtx& setupCtx, uint64_t airgroupId, uint64_t airId, uint64_t instanceId, StepsParams& params, Goldilocks::Element *globalChallenge, uint64_t *proofBuffer, std::string proofFile, std::string proofBinFile = "", bool recursive = false) {
    TimerStart(STARK_PROOF);
    NTT_Goldilocks ntt(1 << setupCtx.starkInfo.starkStruct.nBits);
    NTT_Goldilocks nttExtended(1 << setupCtx.starkInfo.starkStruct.nBitsExt);

    ProverHelpers proverHelpers(setupCtx.starkInfo, false);

    FRIProof<Goldilocks::Element> proof(setupCtx.starkInfo, airgroupId, airId, instanceId);
    
    Starks<Goldilocks::Element> starks(setupCtx, params.pConstPolsExtendedTreeAddress, params.pCustomCommitsFixed);
    
    ExpressionsPack expressionsCtx(setupCtx, &proverHelpers);

    TranscriptGL transcript(setupCtx.starkInfo.starkStruct.transcriptArity, setupCtx.starkInfo.starkStruct.merkleTreeCustom);

    TimerStart(STARK_STEP_0);
    for (uint64_t i = 0; i < setupCtx.starkInfo.customCommits.size(); i++) {
        if(setupCtx.starkInfo.customCommits[i].stageWidths[0] != 0) {
            uint64_t pos = setupCtx.starkInfo.nStages + 2 + i;
            starks.treesGL[pos]->getRoot(&proof.proof.roots[setupCtx.starkInfo.nStages + 1 + i][0]);
            starks.treesGL[pos]->getLevel(&proof.proof.last_levels[setupCtx.starkInfo.nStages + 2 + i][0]);
        }
    }

    starks.treesGL[setupCtx.starkInfo.nStages + 1]->getLevel(&proof.proof.last_levels[setupCtx.starkInfo.nStages + 1][0]);

    if(recursive) {
        Goldilocks::Element verkey[HASH_SIZE];
        starks.treesGL[setupCtx.starkInfo.nStages + 1]->getRoot(verkey);
        starks.addTranscript(transcript, &verkey[0], HASH_SIZE);
        if(setupCtx.starkInfo.nPublics > 0) {
            if(!setupCtx.starkInfo.starkStruct.hashCommits) {
                starks.addTranscriptGL(transcript, &params.publicInputs[0], setupCtx.starkInfo.nPublics);
            } else {
                Goldilocks::Element hash[HASH_SIZE];
                starks.calculateHash(hash, &params.publicInputs[0], setupCtx.starkInfo.nPublics);
                starks.addTranscript(transcript, hash, HASH_SIZE);
            }
        }
    } else {
        starks.addTranscript(transcript, globalChallenge, FIELD_EXTENSION);
    }

    TimerStopAndLog(STARK_STEP_0);

#ifdef CAPTURE_TEST_VECTORS
    // Capture prover inputs for test vector generation (before any proof computation)
    {
        uint64_t N = 1 << setupCtx.starkInfo.starkStruct.nBits;
        uint64_t nColsStage1 = setupCtx.starkInfo.mapSectionsN["cm1"];
        uint64_t nConstPols = setupCtx.starkInfo.nConstants;

        std::cerr << "=== STARK_PROVER_INPUTS_JSON_START ===" << std::endl;
        std::cerr << "{" << std::endl;
        std::cerr << "  \"airgroup\": " << airgroupId << "," << std::endl;
        std::cerr << "  \"air\": " << airId << "," << std::endl;
        std::cerr << "  \"instance\": " << instanceId << "," << std::endl;
        std::cerr << "  \"n_bits\": " << setupCtx.starkInfo.starkStruct.nBits << "," << std::endl;
        std::cerr << "  \"n_cols_stage1\": " << nColsStage1 << "," << std::endl;
        std::cerr << "  \"n_publics\": " << setupCtx.starkInfo.nPublics << "," << std::endl;
        std::cerr << "  \"n_constants\": " << nConstPols << "," << std::endl;

        // Capture global challenge (3 elements for FIELD_EXTENSION)
        std::cerr << "  \"global_challenge\": [";
        for (uint64_t i = 0; i < FIELD_EXTENSION; i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << Goldilocks::toU64(globalChallenge[i]);
        }
        std::cerr << "]," << std::endl;

        // Capture public inputs
        std::cerr << "  \"public_inputs\": [";
        for (uint64_t i = 0; i < setupCtx.starkInfo.nPublics; i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << Goldilocks::toU64(params.publicInputs[i]);
        }
        std::cerr << "]," << std::endl;

        // Capture witness trace (N * nColsStage1 elements)
        std::cerr << "  \"witness_trace\": [";
        uint64_t traceSize = N * nColsStage1;
        for (uint64_t i = 0; i < traceSize; i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << Goldilocks::toU64(params.trace[i]);
        }
        std::cerr << "]," << std::endl;

        // Capture constant polynomials (N * nConstPols elements)
        std::cerr << "  \"const_pols\": [";
        uint64_t constSize = N * nConstPols;
        for (uint64_t i = 0; i < constSize; i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << Goldilocks::toU64(params.pConstPolsAddress[i]);
        }
        std::cerr << "]," << std::endl;

        // Capture transcript state after Step 0 (before Stage 1)
        // transcriptOutSize = 4 * arity, for arity=4, size=16
        uint64_t transcriptSize = 4 * setupCtx.starkInfo.starkStruct.transcriptArity;
        std::cerr << "  \"transcript_state_step0\": {" << std::endl;
        std::cerr << "    \"state\": [";
        for (uint64_t i = 0; i < transcriptSize; i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << Goldilocks::toU64(transcript.state[i]);
        }
        std::cerr << "]," << std::endl;
        std::cerr << "    \"out\": [";
        for (uint64_t i = 0; i < transcriptSize; i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << Goldilocks::toU64(transcript.out[i]);
        }
        std::cerr << "]," << std::endl;
        std::cerr << "    \"out_cursor\": " << transcript.out_cursor << "," << std::endl;
        std::cerr << "    \"pending_cursor\": " << transcript.pending_cursor << std::endl;
        std::cerr << "  }" << std::endl;
        std::cerr << "}" << std::endl;
        std::cerr << "=== STARK_PROVER_INPUTS_JSON_END ===" << std::endl;
    }
#endif

    TimerStart(STARK_STEP_1);
    if(recursive) {
        starks.commitStage(1, params.trace, params.aux_trace, proof, ntt);
        starks.addTranscript(transcript, &proof.proof.roots[0][0], HASH_SIZE);
    } else {
        starks.commitStage(1, params.trace, params.aux_trace, proof, ntt, &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("buff_helper_fft_1", false)]]);
    }
    TimerStopAndLog(STARK_STEP_1);

#ifdef CAPTURE_TEST_VECTORS
    // Capture Stage 1 commitment data for test vector generation
    {
        // Compute hash of extended trace polynomial
        Goldilocks::Element traceExtendedHash[HASH_SIZE];
        uint64_t NExtended = 1 << setupCtx.starkInfo.starkStruct.nBitsExt;
        uint64_t nColsStage1 = setupCtx.starkInfo.mapSectionsN["cm1"];
        Goldilocks::Element* pTraceExtended = &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("cm1", true)]];
        starks.calculateHash(traceExtendedHash, pTraceExtended, NExtended * nColsStage1);

        std::cerr << "=== STARK_STAGE1_JSON_START ===" << std::endl;
        std::cerr << "{" << std::endl;
        std::cerr << "  \"root1\": ["
                  << Goldilocks::toU64(proof.proof.roots[0][0]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[0][1]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[0][2]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[0][3]) << "]," << std::endl;
        std::cerr << "  \"trace_extended_hash\": ["
                  << Goldilocks::toU64(traceExtendedHash[0]) << ", "
                  << Goldilocks::toU64(traceExtendedHash[1]) << ", "
                  << Goldilocks::toU64(traceExtendedHash[2]) << ", "
                  << Goldilocks::toU64(traceExtendedHash[3]) << "]" << std::endl;
        std::cerr << "}" << std::endl;
        std::cerr << "=== STARK_STAGE1_JSON_END ===" << std::endl;
    }
#endif

    TimerStart(STARK_STEP_2);
    TimerStart(STARK_CALCULATE_WITNESS_STD);
    for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++) {
        if(setupCtx.starkInfo.challengesMap[i].stage == 2) {
            starks.getChallenge(transcript, params.challenges[i * FIELD_EXTENSION]);
        }
    }

    calculateWitnessSTD(setupCtx, params, expressionsCtx, true);
    calculateWitnessSTD(setupCtx, params, expressionsCtx, false);
    TimerStopAndLog(STARK_CALCULATE_WITNESS_STD);
    
    TimerStart(CALCULATE_IM_POLS);
    starks.calculateImPolsExpressions(2, params, expressionsCtx);
    TimerStopAndLog(CALCULATE_IM_POLS);

    TimerStart(STARK_COMMIT_STAGE_2);
    if (recursive) {
        starks.commitStage(2, nullptr, params.aux_trace, proof, ntt);
    } else {
        starks.commitStage(2, nullptr, params.aux_trace, proof, ntt, &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("buff_helper_fft_2", false)]]);
    }
    TimerStopAndLog(STARK_COMMIT_STAGE_2);
    starks.addTranscript(transcript, &proof.proof.roots[1][0], HASH_SIZE);

    uint64_t a = 0;
    for(uint64_t i = 0; i < setupCtx.starkInfo.airValuesMap.size(); i++) {
        if(setupCtx.starkInfo.airValuesMap[i].stage == 1) a++;
        if(setupCtx.starkInfo.airValuesMap[i].stage == 2) {
            starks.addTranscript(transcript, &params.airValues[a], FIELD_EXTENSION);
            a += 3;
        }
    }

#ifdef CAPTURE_TEST_VECTORS
    // Capture Stage 2 commitment data for test vector generation
    {
        std::cerr << "=== STARK_STAGE2_JSON_START ===" << std::endl;
        std::cerr << "{" << std::endl;
        std::cerr << "  \"root2\": ["
                  << Goldilocks::toU64(proof.proof.roots[1][0]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[1][1]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[1][2]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[1][3]) << "]," << std::endl;

        // Capture stage 2 challenges
        std::cerr << "  \"challenges_stage2\": [";
        bool firstChallenge = true;
        for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++) {
            if(setupCtx.starkInfo.challengesMap[i].stage == 2) {
                if (!firstChallenge) std::cerr << ", ";
                std::cerr << "["
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION]) << ", "
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION + 1]) << ", "
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION + 2]) << "]";
                firstChallenge = false;
            }
        }
        std::cerr << "]," << std::endl;

        // Capture stage 2 air values
        std::cerr << "  \"air_values_stage2\": [";
        bool firstAirVal = true;
        uint64_t airIdx = 0;
        for(uint64_t i = 0; i < setupCtx.starkInfo.airValuesMap.size(); i++) {
            if(setupCtx.starkInfo.airValuesMap[i].stage == 1) airIdx++;
            if(setupCtx.starkInfo.airValuesMap[i].stage == 2) {
                if (!firstAirVal) std::cerr << ", ";
                std::cerr << "["
                          << Goldilocks::toU64(params.airValues[airIdx]) << ", "
                          << Goldilocks::toU64(params.airValues[airIdx + 1]) << ", "
                          << Goldilocks::toU64(params.airValues[airIdx + 2]) << "]";
                firstAirVal = false;
                airIdx += 3;
            }
        }
        std::cerr << "]" << std::endl;
        std::cerr << "}" << std::endl;
        std::cerr << "=== STARK_STAGE2_JSON_END ===" << std::endl;
    }
#endif

    TimerStopAndLog(STARK_STEP_2);

    TimerStart(STARK_STEP_Q);

    for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++)
    {
        if(setupCtx.starkInfo.challengesMap[i].stage == setupCtx.starkInfo.nStages + 1) {
            starks.getChallenge(transcript, params.challenges[i * FIELD_EXTENSION]);
        }
    }

    TimerStart(STARK_CALCULATE_QUOTIENT_POLYNOMIAL);
    starks.calculateQuotientPolynomial(params, expressionsCtx);
    TimerStopAndLog(STARK_CALCULATE_QUOTIENT_POLYNOMIAL);

    TimerStart(STARK_COMMIT_QUOTIENT_POLYNOMIAL);
    if (recursive) {
        starks.commitStage(setupCtx.starkInfo.nStages + 1, nullptr, params.aux_trace, proof, nttExtended);
    } else {
        starks.commitStage(setupCtx.starkInfo.nStages + 1, nullptr, params.aux_trace, proof, nttExtended, &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("buff_helper_fft_3", false)]]);
    }
    TimerStopAndLog(STARK_COMMIT_QUOTIENT_POLYNOMIAL);
    starks.addTranscript(transcript, &proof.proof.roots[setupCtx.starkInfo.nStages][0], HASH_SIZE);

#ifdef CAPTURE_TEST_VECTORS
    // Capture Stage Q (Quotient) commitment data for test vector generation
    {
        // Compute hash of quotient polynomial
        Goldilocks::Element quotientPolyHash[HASH_SIZE];
        uint64_t NExtended = 1 << setupCtx.starkInfo.starkStruct.nBitsExt;
        uint64_t nColsQ = setupCtx.starkInfo.mapSectionsN["cm" + std::to_string(setupCtx.starkInfo.nStages + 1)];
        Goldilocks::Element* pQuotient = &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("q", true)]];
        starks.calculateHash(quotientPolyHash, pQuotient, NExtended * nColsQ);

        std::cerr << "=== STARK_STAGEQ_JSON_START ===" << std::endl;
        std::cerr << "{" << std::endl;
        std::cerr << "  \"rootQ\": ["
                  << Goldilocks::toU64(proof.proof.roots[setupCtx.starkInfo.nStages][0]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[setupCtx.starkInfo.nStages][1]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[setupCtx.starkInfo.nStages][2]) << ", "
                  << Goldilocks::toU64(proof.proof.roots[setupCtx.starkInfo.nStages][3]) << "]," << std::endl;
        std::cerr << "  \"quotient_poly_hash\": ["
                  << Goldilocks::toU64(quotientPolyHash[0]) << ", "
                  << Goldilocks::toU64(quotientPolyHash[1]) << ", "
                  << Goldilocks::toU64(quotientPolyHash[2]) << ", "
                  << Goldilocks::toU64(quotientPolyHash[3]) << "]," << std::endl;

        // Capture stage Q challenges
        std::cerr << "  \"challenges_stageQ\": [";
        bool firstChallenge = true;
        for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++) {
            if(setupCtx.starkInfo.challengesMap[i].stage == setupCtx.starkInfo.nStages + 1) {
                if (!firstChallenge) std::cerr << ", ";
                std::cerr << "["
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION]) << ", "
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION + 1]) << ", "
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION + 2]) << "]";
                firstChallenge = false;
            }
        }
        std::cerr << "]" << std::endl;
        std::cerr << "}" << std::endl;
        std::cerr << "=== STARK_STAGEQ_JSON_END ===" << std::endl;
    }
#endif

    TimerStopAndLog(STARK_STEP_Q);

    TimerStart(STARK_STEP_EVALS);

    uint64_t xiChallengeIndex = 0;
    for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++)
    {
        if(setupCtx.starkInfo.challengesMap[i].stage == setupCtx.starkInfo.nStages + 2) {
            if(setupCtx.starkInfo.challengesMap[i].stageId == 0) xiChallengeIndex = i;
            starks.getChallenge(transcript, params.challenges[i * FIELD_EXTENSION]);
        }
    }

    Goldilocks::Element *xiChallenge = &params.challenges[xiChallengeIndex * FIELD_EXTENSION];
    Goldilocks::Element* LEv = &params.aux_trace[setupCtx.starkInfo.mapOffsets[make_pair("lev", false)]];

    for(uint64_t i = 0; i < setupCtx.starkInfo.openingPoints.size(); i += 4) {
        std::vector<int64_t> openingPoints;
        for(uint64_t j = 0; j < 4; ++j) {
            if(i + j < setupCtx.starkInfo.openingPoints.size()) {
                openingPoints.push_back(setupCtx.starkInfo.openingPoints[i + j]);
            }
        }
        starks.computeLEv(xiChallenge, LEv, openingPoints, ntt);
        starks.computeEvals(params ,LEv, proof, openingPoints);
    }
    

    if(!setupCtx.starkInfo.starkStruct.hashCommits) {
        starks.addTranscriptGL(transcript, params.evals, setupCtx.starkInfo.evMap.size() * FIELD_EXTENSION);
    } else {
        Goldilocks::Element hash[HASH_SIZE];
        starks.calculateHash(hash, params.evals, setupCtx.starkInfo.evMap.size() * FIELD_EXTENSION);
        starks.addTranscript(transcript, hash, HASH_SIZE);
    }
    // Challenges for FRI polynomial
    for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++)
    {
        if(setupCtx.starkInfo.challengesMap[i].stage == setupCtx.starkInfo.nStages + 3) {
            starks.getChallenge(transcript, params.challenges[i * FIELD_EXTENSION]);
        }
    }

#ifdef CAPTURE_TEST_VECTORS
    // Capture Stage EVALS (Evaluations) data for test vector generation
    {
        // Compute hash of Lagrange evaluation polynomial
        Goldilocks::Element LEvHash[HASH_SIZE];
        uint64_t N = 1 << setupCtx.starkInfo.starkStruct.nBits;
        uint64_t nOpeningPoints = setupCtx.starkInfo.openingPoints.size();
        Goldilocks::Element* pLEv = &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("lev", false)]];
        starks.calculateHash(LEvHash, pLEv, N * nOpeningPoints * FIELD_EXTENSION);

        std::cerr << "=== STARK_EVALS_JSON_START ===" << std::endl;
        std::cerr << "{" << std::endl;

        // Capture evaluations
        std::cerr << "  \"evals\": [";
        for (uint64_t i = 0; i < setupCtx.starkInfo.evMap.size(); i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << "["
                      << Goldilocks::toU64(params.evals[i * FIELD_EXTENSION]) << ", "
                      << Goldilocks::toU64(params.evals[i * FIELD_EXTENSION + 1]) << ", "
                      << Goldilocks::toU64(params.evals[i * FIELD_EXTENSION + 2]) << "]";
        }
        std::cerr << "]," << std::endl;

        std::cerr << "  \"LEv_hash\": ["
                  << Goldilocks::toU64(LEvHash[0]) << ", "
                  << Goldilocks::toU64(LEvHash[1]) << ", "
                  << Goldilocks::toU64(LEvHash[2]) << ", "
                  << Goldilocks::toU64(LEvHash[3]) << "]," << std::endl;

        std::cerr << "  \"xi_challenge\": ["
                  << Goldilocks::toU64(xiChallenge[0]) << ", "
                  << Goldilocks::toU64(xiChallenge[1]) << ", "
                  << Goldilocks::toU64(xiChallenge[2]) << "]," << std::endl;

        // Capture FRI polynomial challenges (stage nStages + 3)
        std::cerr << "  \"challenges_fri\": [";
        bool firstChallenge = true;
        for (uint64_t i = 0; i < setupCtx.starkInfo.challengesMap.size(); i++) {
            if(setupCtx.starkInfo.challengesMap[i].stage == setupCtx.starkInfo.nStages + 3) {
                if (!firstChallenge) std::cerr << ", ";
                std::cerr << "["
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION]) << ", "
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION + 1]) << ", "
                          << Goldilocks::toU64(params.challenges[i * FIELD_EXTENSION + 2]) << "]";
                firstChallenge = false;
            }
        }
        std::cerr << "]" << std::endl;
        std::cerr << "}" << std::endl;
        std::cerr << "=== STARK_EVALS_JSON_END ===" << std::endl;
    }
#endif

    TimerStopAndLog(STARK_STEP_EVALS);

    //--------------------------------
    // 6. Compute FRI
    //--------------------------------
    TimerStart(STARK_STEP_FRI);

    TimerStart(COMPUTE_FRI_POLYNOMIAL);
    starks.calculateFRIPolynomial(params, expressionsCtx);
    TimerStopAndLog(COMPUTE_FRI_POLYNOMIAL);

    Goldilocks::Element *friPol = &params.aux_trace[setupCtx.starkInfo.mapOffsets[std::make_pair("f", true)]];

#ifdef CAPTURE_TEST_VECTORS
    // Capture FRI input polynomial for test vector generation (JSON format)
    {
        uint64_t friPolSize = (1ULL << setupCtx.starkInfo.starkStruct.steps[0].nBits) * FIELD_EXTENSION;

        // Also compute hash of input polynomial for validation
        Goldilocks::Element inputHash[HASH_SIZE];
        TranscriptGL hashTranscript(setupCtx.starkInfo.starkStruct.transcriptArity,
                                    setupCtx.starkInfo.starkStruct.merkleTreeCustom);
        hashTranscript.put(friPol, friPolSize);
        hashTranscript.getState(inputHash);

        // Output JSON block with clear delimiters
        std::cerr << "=== FRI_GEN_PROOF_JSON_START ===" << std::endl;
        std::cerr << "{" << std::endl;
        std::cerr << "  \"airgroup\": " << airgroupId << "," << std::endl;
        std::cerr << "  \"air\": " << airId << "," << std::endl;
        std::cerr << "  \"instance\": " << instanceId << "," << std::endl;
        std::cerr << "  \"fri_pol_size\": " << friPolSize << "," << std::endl;
        std::cerr << "  \"fri_input_polynomial\": [";
        for (uint64_t i = 0; i < friPolSize; i++) {
            if (i > 0) std::cerr << ", ";
            std::cerr << Goldilocks::toU64(friPol[i]);
        }
        std::cerr << "]," << std::endl;
        std::cerr << "  \"fri_input_pol_hash\": ["
                  << Goldilocks::toU64(inputHash[0]) << ", "
                  << Goldilocks::toU64(inputHash[1]) << ", "
                  << Goldilocks::toU64(inputHash[2]) << ", "
                  << Goldilocks::toU64(inputHash[3]) << "]" << std::endl;
        std::cerr << "}" << std::endl;
        std::cerr << "=== FRI_GEN_PROOF_JSON_END ===" << std::endl;
    }
#endif

    // Build FRI PCS configuration from stark structure
    const FriPcsConfig friConfig {
        .n_bits_ext = setupCtx.starkInfo.starkStruct.steps[0].nBits,
        .fri_steps = [&]() {
            std::vector<uint64_t> steps;
            steps.reserve(setupCtx.starkInfo.starkStruct.steps.size());
            for (const auto& step : setupCtx.starkInfo.starkStruct.steps) {
                steps.push_back(step.nBits);
            }
            return steps;
        }(),
        .n_queries = setupCtx.starkInfo.starkStruct.nQueries,
        .merkle_arity = setupCtx.starkInfo.starkStruct.merkleTreeArity,
        .pow_bits = setupCtx.starkInfo.starkStruct.powBits,
        .last_level_verification = 0,
        .hash_commits = setupCtx.starkInfo.starkStruct.hashCommits,
        .transcript_arity = setupCtx.starkInfo.starkStruct.transcriptArity,
        .merkle_tree_custom = setupCtx.starkInfo.starkStruct.merkleTreeCustom,
    };

    // Create FriPcs with external trees (owned by Starks)
    FriPcs<MerkleTreeGL> friPcs(friConfig);
    uint64_t numFriTrees = setupCtx.starkInfo.starkStruct.steps.size() > 0 ?
                           setupCtx.starkInfo.starkStruct.steps.size() - 1 : 0;
    friPcs.setExternalTrees(starks.treesFRI, numFriTrees);

    // Execute FRI proof (handles folding, merkleization, grinding, and queries)
    uint64_t nTrees = setupCtx.starkInfo.nStages + setupCtx.starkInfo.customCommits.size() + 2;
    const uint64_t nonce = friPcs.prove(friPol, proof, transcript, nTrees, starks.treesGL);

    TimerStopAndLog(STARK_STEP_FRI);

    proof.proof.setEvals(params.evals);
    proof.proof.setAirgroupValues(params.airgroupValues);
    proof.proof.setAirValues(params.airValues);
    proof.proof.setNonce(nonce);

    proof.proof.proof2pointer(proofBuffer);

    if(!proofFile.empty()) {
        json2file(pointer2json(proofBuffer, setupCtx.starkInfo), proofFile);

#ifdef CAPTURE_TEST_VECTORS
        // When capturing test vectors, also save raw binary proof
        std::string binFile = proofFile;
        size_t dotPos = binFile.rfind(".json");
        if (dotPos != std::string::npos) {
            binFile = binFile.substr(0, dotPos) + ".proof.bin";
        } else {
            binFile += ".proof.bin";
        }
        std::ofstream binOut(binFile, std::ios::binary);
        binOut.write(reinterpret_cast<const char*>(proofBuffer),
                     setupCtx.starkInfo.proofSize * sizeof(uint64_t));
#endif
    }

    if(!proofBinFile.empty()) {
        std::ofstream binOut(proofBinFile, std::ios::binary);
        binOut.write(reinterpret_cast<const char*>(proofBuffer),
                     setupCtx.starkInfo.proofSize * sizeof(uint64_t));
    }

    TimerStopAndLog(STARK_PROOF);    
}
