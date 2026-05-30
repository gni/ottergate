import os
import sys

def verify_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Package declaration check
    lines = content.splitlines()
    has_package = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('package '):
            has_package = True
            break
        if stripped and not stripped.startswith('//') and not stripped.startswith('/*') and not stripped.startswith('*'):
            # Found non-comment line before package
            break
            
    if not has_package:
        return False, "Missing package declaration"
        
    # 2. Balanced brackets, braces, and parentheses check
    stack = []
    mapping = {')': '(', ']': '[', '}': '{'}
    line_no = 1
    col_no = 1
    
    in_string = False
    in_char = False
    in_line_comment = False
    in_block_comment = False
    escape = False
    
    i = 0
    while i < len(content):
        char = content[i]
        
        # Track line and column numbers
        if char == '\n':
            line_no += 1
            col_no = 1
        else:
            col_no += 1
            
        if escape:
            escape = False
            i += 1
            continue
            
        # Handle Block Comments
        if in_block_comment:
            if char == '*' and i + 1 < len(content) and content[i+1] == '/':
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
            
        # Handle Line Comments
        if in_line_comment:
            if char == '\n':
                in_line_comment = False
            i += 1
            continue
            
        # Handle double quoted strings
        if in_string:
            if char == '\\':
                escape = True
            elif char == '"':
                in_string = False
            i += 1
            continue
            
        # Handle single quoted runes
        if in_char:
            if char == '\\':
                escape = True
            elif char == "'":
                in_char = False
            i += 1
            continue
            
        # Check comment start
        if char == '/' and i + 1 < len(content):
            if content[i+1] == '/':
                in_line_comment = True
                i += 2
                continue
            elif content[i+1] == '*':
                in_block_comment = True
                i += 2
                continue
                
        # String start
        if char == '"':
            in_string = True
            i += 1
            continue
            
        # Raw string backtick
        if char == '`':
            # find next backtick
            next_idx = content.find('`', i + 1)
            if next_idx == -1:
                return False, f"Unclosed raw string literal starting at line {line_no}"
            # skip raw string
            # count lines in raw string to update line_no
            line_no += content[i:next_idx].count('\n')
            i = next_idx + 1
            continue
            
        # Rune start
        if char == "'":
            in_char = True
            i += 1
            continue
            
        # Braces tracking
        if char in '({[':
            stack.append((char, line_no, col_no))
        elif char in ')}]':
            if not stack:
                return False, f"Unmatched closing character {char} at line {line_no}, column {col_no}"
            top, t_line, t_col = stack.pop()
            if mapping[char] != top:
                return False, f"Mismatched closing character {char} at line {line_no}, col {col_no}. Opened as {top} at line {t_line}, col {t_col}"
                
        i += 1
        
    if stack:
        top, t_line, t_col = stack[-1]
        return False, f"Unclosed opening character {top} at line {t_line}, column {t_col}"
        
    return True, "Success"

def main():
    # Scan from the project parent (root) folder to find all Go files
    target_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    go_files = []
    for root, _, files in os.walk(target_dir):
        for f in files:
            if f.endswith('.go'):
                go_files.append(os.path.join(root, f))
                
    success = True
    print(f"Starting static syntax verification of {len(go_files)} Go source files...\n")
    for filepath in sorted(go_files):
        rel_path = os.path.relpath(filepath, target_dir)
        ok, msg = verify_file(filepath)
        if ok:
            print(f"  [ PASS ] {rel_path}")
        else:
            print(f"  [ FAIL ] {rel_path} : {msg}")
            success = False
            
    print("\n--------------------------------------------------")
    if success:
        print("STATIC VERIFICATION COMPLETE: ALL FILES PASSED!")
        sys.exit(0)
    else:
        print("STATIC VERIFICATION FAILED: Fix reported errors.")
        sys.exit(1)

if __name__ == '__main__':
    main()
