import os
from dotenv import load_dotenv
from pathlib import Path

print("=" * 50)
print("Testing .env loading...")
print("=" * 50)

# Get absolute path to .env
env_path = Path(__file__).parent / '.env'
print(f"Looking for .env at: {env_path}")
print(f"File exists: {env_path.exists()}")

if env_path.exists():
    # Load with explicit path
    load_dotenv(dotenv_path=env_path, override=True)
    print("✅ .env file loaded successfully")
    
    # Read and display the actual content (masking token)
    with open(env_path, 'r') as f:
        print("\n📄 .env contents:")
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if 'TOKEN' in line:
                    key, value = line.split('=', 1)
                    masked = key + '=' + '*' * min(len(value), 10) + ('...' if len(value) > 10 else '')
                    print(f"  {masked}")
                else:
                    print(f"  {line}")
else:
    print("❌ .env file NOT found!")
    print(f"Current directory: {os.getcwd()}")

print("\n" + "=" * 50)
print("Environment variables after loading:")
print("=" * 50)

url = os.getenv('http://localhost/redcap/redcap_v14.1.6/API/project_api.php?pid=16')
token = os.getenv('4DA5AC5A9C3FDA640F4C6F4502C1BAFC')

print(f"REDCAP_API_URL: {url}")
print(f"REDCAP_API_TOKEN: {'[SET]' if token else '[NOT SET]'}")
if token:
    print(f"Token length: {len(token)}")
    print(f"Token preview: {token[:10]}...")
print("=" * 50)