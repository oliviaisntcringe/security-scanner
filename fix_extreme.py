#!/usr/bin/env python3

def fix_function():
    filename = 'app/utils/helpers.py'
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    # Find the save_history function
    start_idx = -1
    end_idx = -1
    
    for i, line in enumerate(lines):
        if 'def save_history' in line:
            start_idx = i
        if start_idx != -1 and end_idx == -1 and line.strip() == '':
            end_idx = i
    
    if end_idx == -1:
        end_idx = len(lines)
    
    if start_idx == -1:
        print("Function not found!")
        return
    
    # Create a replacement function with carefully controlled indentation
    replacement = [
        "def save_history(history: Set[str]) -> None:\n",
        "    \"\"\"Save scan history to file\"\"\"\n",
        "    try:\n",
        "        history_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'history.json')\n",
        "        os.makedirs(os.path.dirname(history_path), exist_ok=True)\n",
        "        with open(history_path, 'w') as f:\n",
        "            json.dump(list(history), f)\n",
        "    except Exception as e:\n",
        "        LOG(f\"[!] Error saving history: {e}\", \"ERROR\")\n",
        "        import traceback\n",
        "        LOG(traceback.format_exc(), \"ERROR\")\n",
        "\n"
    ]
    
    # Replace the old function with the new one
    lines[start_idx:end_idx] = replacement
    
    # Write the fixed file
    with open(filename, 'w') as f:
        f.writelines(lines)
    
    print(f"Function replaced from line {start_idx+1} to {end_idx}")

if __name__ == "__main__":
    fix_function() 