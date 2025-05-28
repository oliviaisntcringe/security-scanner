#!/usr/bin/env python3

def check_and_fix_whitespace():
    filename = 'app/utils/helpers.py'
    
    # Read the file in binary mode to detect all whitespace characters
    with open(filename, 'rb') as f:
        lines = f.readlines()
    
    # Find the save_history function
    start_idx = -1
    for i, line in enumerate(lines):
        if b'def save_history' in line:
            start_idx = i
            break
    
    if start_idx == -1:
        print("Function not found!")
        return
    
    # Analyze the lines around the indentation issue
    print("Binary representation of key lines:")
    for i in range(start_idx + 4, start_idx + 8):  # Lines around the json.dump line
        line = lines[i]
        print(f"Line {i+1}: ", end='')
        
        # Print each character with its ASCII/byte representation
        for idx, char in enumerate(line):
            if idx < 20:  # Only show the first 20 characters for brevity
                print(f"{char:02x}({chr(char) if 32 <= char <= 126 else '?'})", end=' ')
        print()
    
    # Check specifically for mixed tabs/spaces in the indentation
    json_dump_line = -1
    for i in range(start_idx, min(start_idx + 15, len(lines))):
        if b'json.dump' in lines[i]:
            json_dump_line = i
            break
    
    if json_dump_line != -1:
        line = lines[json_dump_line]
        indentation = []
        for char in line:
            if char == 32:  # space
                indentation.append('S')
            elif char == 9:  # tab
                indentation.append('T')
            else:
                break
        
        print(f"\nIndentation pattern for json.dump line (line {json_dump_line+1}):")
        print(''.join(indentation))
        
        # Fix the line if there's a mix of tabs and spaces
        if 'T' in indentation and 'S' in indentation:
            # Replace with consistent spaces (4 spaces per tab)
            fixed_line = b' ' * 12 + line.lstrip()
            lines[json_dump_line] = fixed_line
            
            # Write the fixed content back
            with open(filename, 'wb') as f:
                f.writelines(lines)
            print("\nFile fixed! Mixed tabs and spaces in indentation were replaced with spaces.")
            return
        
        # Also check if indentation is incorrect
        if len(indentation) != 12:
            # Should have 12 spaces (3 levels of indentation)
            fixed_line = b' ' * 12 + line.lstrip()
            lines[json_dump_line] = fixed_line
            
            # Write the fixed content back
            with open(filename, 'wb') as f:
                f.writelines(lines)
            print(f"\nFile fixed! Indentation was {len(indentation)} spaces, changed to 12 spaces.")
            return
    
    print("\nNo indentation issues found that could be fixed.")

if __name__ == "__main__":
    check_and_fix_whitespace() 