#!/usr/bin/env python3

def fix_indentation():
    filename = 'app/utils/helpers.py'
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    # Find the save_history function
    start_idx = -1
    for i, line in enumerate(lines):
        if 'def save_history' in line:
            start_idx = i
            break
    
    if start_idx == -1:
        print("Function not found!")
        return
    
    # Print the current function for debugging
    print("Current function:")
    for i in range(start_idx, min(start_idx + 15, len(lines))):
        print(f"{i+1}: {lines[i]}", end='')
    
    # Check and fix any indentation issues in json.dump line
    for i in range(start_idx, min(start_idx + 15, len(lines))):
        if 'json.dump' in lines[i]:
            print(f"\nChecking line {i+1}: {repr(lines[i])}")
            if not lines[i].startswith('            '):
                lines[i] = '            ' + lines[i].lstrip()
                print(f"Fixed to: {repr(lines[i])}")
                
                # Write the fixed content back
                with open(filename, 'w') as f:
                    f.writelines(lines)
                print("\nFile fixed!")
                return
    
    print("No indentation issues found in the json.dump line.")

if __name__ == "__main__":
    fix_indentation() 