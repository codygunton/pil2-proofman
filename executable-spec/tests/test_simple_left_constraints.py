

def test_simple_left_constraint_module_loads() -> None:
    from constraints.simple_left import SimpleLeftConstraints
    module = SimpleLeftConstraints()
    assert hasattr(module, 'constraint_polynomial')
