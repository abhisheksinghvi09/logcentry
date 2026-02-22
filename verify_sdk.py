import logcentry.sdk as lc
import time
import sys
import logging

# Configure logging to see SDK internal logs
logging.basicConfig(level=logging.DEBUG)

print("--- LogCentry SDK Verification ---")

try:
    print("1. Initializing SDK...")
    # Use sync mode to see immediate results in logs, or async mode to test background thread
    agent = lc.init(api_key="lc_test_key", sync_mode=True) 
    print(f"   Agent initialized: {agent}")

    print("\n2. Logging INFO message...")
    lc.info("Hello World", user="test_user", action="login")
    print("   Logged info.")

    print("\n3. Logging ERROR message...")
    lc.error("Simulated failure", error_code=500)
    print("   Logged error.")

    print("\n4. Testing @log_capture decorator...")
    @lc.log_capture()
    def calculate(x, y):
        print(f"   Executing calculate({x}, {y})")
        return x + y

    result = calculate(10, 20)
    print(f"   Result: {result}")

    print("\n5. Testing Singleton access...")
    agent2 = lc.get_agent()
    print(f"   Agents match: {agent is agent2}")

    print("\n6. Shutting down...")
    lc.shutdown()
    print("   Shutdown complete.")
    
except Exception as e:
    print(f"\n❌ Verification Failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n✅ Verification Passed!")
