#!/usr/bin/env python3
"""
Test the cognitive architecture components.
"""

import os
import sys
from unittest.mock import Mock, MagicMock

# Set up environment for testing
os.environ["GOOGLE_API_KEY"] = "test_key"
os.environ["ENABLE_COGNITIVE_MODE"] = "true"
os.environ["ENABLE_HEADLESS_BROWSER"] = "false"

def test_cognitive_agents_import():
    """Test that cognitive agents can be imported."""
    try:
        from cognitive_agents import PlannerAgent, ExecutorAgent, CriticAgent
        print("✓ Cognitive agents import successful")
        return True
    except Exception as e:
        print(f"✗ Failed to import cognitive agents: {e}")
        return False

def test_planner_agent_creation():
    """Test PlannerAgent can be instantiated."""
    try:
        from cognitive_agents import PlannerAgent
        
        # Mock model
        mock_model = Mock()
        planner = PlannerAgent(mock_model)
        
        assert planner is not None
        assert hasattr(planner, 'create_scanning_plan')
        assert hasattr(planner, 'plans')
        
        print("✓ PlannerAgent instantiation successful")
        return True
    except Exception as e:
        print(f"✗ PlannerAgent instantiation failed: {e}")
        return False

def test_executor_agent_creation():
    """Test ExecutorAgent can be instantiated."""
    try:
        from cognitive_agents import ExecutorAgent
        
        # Mock execute function
        def mock_execute(cmd):
            return True, "test output"
        
        executor = ExecutorAgent(mock_execute)
        
        assert executor is not None
        assert hasattr(executor, 'execute_plan')
        assert hasattr(executor, 'execution_history')
        
        print("✓ ExecutorAgent instantiation successful")
        return True
    except Exception as e:
        print(f"✗ ExecutorAgent instantiation failed: {e}")
        return False

def test_critic_agent_creation():
    """Test CriticAgent can be instantiated."""
    try:
        from cognitive_agents import CriticAgent
        
        # Mock model
        mock_model = Mock()
        critic = CriticAgent(mock_model)
        
        assert critic is not None
        assert hasattr(critic, 'validate_finding')
        assert hasattr(critic, 'validations')
        
        print("✓ CriticAgent instantiation successful")
        return True
    except Exception as e:
        print(f"✗ CriticAgent instantiation failed: {e}")
        return False

def test_pattern_validation():
    """Test CriticAgent pattern-based validation."""
    try:
        from cognitive_agents import CriticAgent
        
        mock_model = Mock()
        critic = CriticAgent(mock_model)
        
        # Test SQL injection evidence
        sql_output = "MySQL syntax error near '1''"
        result = critic._pattern_based_validation(sql_output, "sql")
        assert result["has_evidence"] == True
        print("✓ Pattern validation for SQL injection works")
        
        # Test no evidence
        normal_output = "Welcome to our website"
        result = critic._pattern_based_validation(normal_output, "sql")
        assert result["has_evidence"] == False
        print("✓ Pattern validation correctly rejects non-vulnerabilities")
        
        return True
    except Exception as e:
        print(f"✗ Pattern validation failed: {e}")
        return False

def test_command_extraction():
    """Test PlannerAgent command extraction."""
    try:
        from cognitive_agents import PlannerAgent
        
        mock_model = Mock()
        planner = PlannerAgent(mock_model)
        
        plan_text = """
        Here's the strategy:
        1. First, run: curl -s https://example.com
        2. Then try: nmap -p 80,443 example.com
        3. Also test with: wget https://example.com
        """
        
        commands = planner._extract_commands_from_plan(plan_text, "example.com")
        
        assert len(commands) > 0
        assert any("curl" in cmd for cmd in commands)
        print(f"✓ Command extraction works (found {len(commands)} commands)")
        
        return True
    except Exception as e:
        print(f"✗ Command extraction failed: {e}")
        return False

def test_executor_plan_execution():
    """Test ExecutorAgent plan execution."""
    try:
        from cognitive_agents import ExecutorAgent
        
        execution_count = [0]
        
        def mock_execute(cmd):
            execution_count[0] += 1
            return True, f"Output for: {cmd}"
        
        executor = ExecutorAgent(mock_execute)
        
        plan = {
            "phase": "test",
            "commands": [
                "curl -s https://example.com",
                "curl -I https://example.com"
            ]
        }
        
        results = executor.execute_plan(plan)
        
        assert len(results) == 2
        assert execution_count[0] == 2
        assert all(r["success"] for r in results)
        print("✓ ExecutorAgent plan execution works")
        
        return True
    except Exception as e:
        print(f"✗ Executor plan execution failed: {e}")
        return False

def test_bug_bounty_agent_with_cognitive_mode():
    """Test BugBountyAgent with cognitive mode enabled."""
    try:
        # Mock google.generativeai
        import sys
        from unittest.mock import MagicMock
        
        mock_genai = MagicMock()
        sys.modules['google.generativeai'] = mock_genai
        
        from bug_bounty_agent import BugBountyAgent
        
        agent = BugBountyAgent()
        
        assert hasattr(agent, 'planner')
        assert hasattr(agent, 'executor')
        assert hasattr(agent, 'critic')
        assert agent.enable_cognitive_mode == True
        
        print("✓ BugBountyAgent with cognitive mode initialization successful")
        return True
    except Exception as e:
        print(f"✗ BugBountyAgent cognitive mode failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("Testing Cognitive Architecture")
    print("=" * 60)
    print()
    
    tests = [
        test_cognitive_agents_import,
        test_planner_agent_creation,
        test_executor_agent_creation,
        test_critic_agent_creation,
        test_pattern_validation,
        test_command_extraction,
        test_executor_plan_execution,
        test_bug_bounty_agent_with_cognitive_mode,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} raised exception: {e}")
            failed += 1
        print()
    
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
