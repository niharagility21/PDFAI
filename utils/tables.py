import re
import os
import json
import logging
import pandas as pd

app_logger = logging.getLogger('pdf_analyzer')

def clean_number(text):
    """Clean and format numeric values."""
    if not isinstance(text, str):
        return text
        
    # Handle LaTeX math expressions
    if '$' in text:
        # Check if this is an actual LaTeX expression (enclosed in $ signs)
        if text.startswith('$') and text.endswith('$'):
            inner_text = text[1:-1].strip()  # Remove outer dollar signs
            return clean_number(inner_text)
        
        # Check for nested LaTeX expressions
        matches = re.findall(r'\$(.*?)\$', text)
        if matches:
            for match in matches:
                inner_processed = clean_number(match)
                text = text.replace(f"${match}$", str(inner_processed))
    
    # Special case: if this appears to be a description with a currency value inside parentheses
    description_with_currency = re.search(r'^(.*?)(\([\$\\].*?\))(.*?)$', text)
    if description_with_currency:
        prefix = description_with_currency.group(1).strip()
        currency_part = description_with_currency.group(2)
        suffix = description_with_currency.group(3).strip()
        
        # Replace escaped dollar signs in the currency part
        currency_part = currency_part.replace('\\$', '$')
        
        # Reconstruct the text with properly formatted currency in parentheses
        return f"{prefix} {currency_part} {suffix}".strip()
    
    # Replace escaped characters but preserve structure
    text = re.sub(r'\\(.)', r'\1', text)
    
    # Handle negative amounts properly
    if text.startswith('$') and text.endswith('$') and '-' in text:
        # Special case: negative dollar amounts, retain the negative sign and dollar sign
        clean_text = text[1:-1].strip()  # Remove outer dollar signs
        return f"${clean_text}"

    # Return the cleaned text
    return text

def extract_tables_from_markdown(markdown):
    """Extract tables from markdown text."""
    app_logger.debug("Extracting tables from markdown")
    tables = []
    current_table = []
    in_table = False
    
    lines = markdown.split('\n')
    for line in lines:
        line = line.strip()
        
        # Check if line is part of a table (starts and ends with |)
        if line.startswith('|') and line.endswith('|'):
            if not in_table:
                in_table = True
                current_table = []
            
            # Add to current table
            current_table.append(line)
        else:
            # If we were in a table but this line is not a table row
            if in_table:
                in_table = False
                if len(current_table) > 1:  # Real table has at least 2 rows
                    tables.append(current_table)
                current_table = []
    
    # Don't forget the last table if file ends with a table
    if in_table and len(current_table) > 1:
        tables.append(current_table)
    
    app_logger.info(f"Extracted {len(tables)} tables from markdown")
    return tables

def parse_table(table_lines):
    """Parse table lines with improved formatting."""
    app_logger.debug(f"Parsing table with {len(table_lines)} lines")
    
    # Get headers
    header_row = table_lines[0]
    headers = [cell.strip() for cell in header_row.split('|')]
    headers = [h for h in headers if h]  # Remove empty strings
    
    # Handle separator row
    start_idx = 1
    if len(table_lines) > 1 and re.search(r'[-:|]+', table_lines[1]):
        start_idx = 2
    
    # Process rows with enhanced cleaning
    processed_rows = []
    last_item_row_idx = -1
    
    for i in range(start_idx, len(table_lines)):
        line = table_lines[i]
        raw_cells = line.split('|')
        
        # Skip line if not enough cells
        if len(raw_cells) <= 2:
            continue
            
        # Keep original cell structure
        cells = [cell.strip() for cell in raw_cells[1:-1]]
        
        # Skip completely empty rows
        if all(not c for c in cells):
            continue
        
        # Date row detection
        date_pattern = r'\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s*-\s*\w+\s+\d{1,2},?\s+\d{4}\b'
        if len(cells) == 1 and re.search(date_pattern, cells[0]) and last_item_row_idx >= 0:
            # Attach to previous item
            processed_rows[last_item_row_idx][0] = f"{processed_rows[last_item_row_idx][0]}\n{cells[0]}"
            continue
            
        # Clean cells while preserving content
        clean_cells = []
        
        for j, cell in enumerate(cells):
            if j >= len(headers):
                continue
                
            # Clean the cell content
            cleaned_cell = clean_number(cell)
            clean_cells.append(cleaned_cell)
        
        # Pad with empty strings as needed
        while len(clean_cells) < len(headers):
            clean_cells.append("")
        
        # Add to processed rows
        processed_rows.append(clean_cells)
        
        # Track last regular item row
        if len(cells) == len(headers) and cells[0]:  # Regular item row has content in first cell
            last_item_row_idx = len(processed_rows) - 1
    
    # Create DataFrame with enhanced formatting
    df = pd.DataFrame(processed_rows, columns=headers).fillna("")
    
    # Additional formatting for common data types
    for col in df.columns:
        # Try to detect and format currency columns
        if any('$' in str(val) for val in df[col] if str(val).strip()):
            continue  # Keep currency formatting as is
        
        # Try to detect and format numeric columns
        numeric_vals = []
        for val in df[col]:
            val_str = str(val).strip()
            if val_str and val_str != '':
                # Try to extract numbers
                num_match = re.search(r'[-+]?\d*\.?\d+', val_str)
                if num_match and len(val_str.replace(num_match.group(), '').strip()) <= 3:
                    try:
                        numeric_vals.append(float(num_match.group()))
                    except:
                        break
                else:
                    break
        
        # If most values are numeric, format consistently
        if len(numeric_vals) > len(df) * 0.7:  # 70% numeric threshold
            for i, val in enumerate(df[col]):
                val_str = str(val).strip()
                if val_str:
                    num_match = re.search(r'[-+]?\d*\.?\d+', val_str)
                    if num_match:
                        try:
                            num = float(num_match.group())
                            # Format with appropriate decimal places
                            if num == int(num):
                                df.iloc[i, df.columns.get_loc(col)] = str(int(num))
                            else:
                                df.iloc[i, df.columns.get_loc(col)] = f"{num:.2f}"
                        except:
                            pass
    
    app_logger.debug(f"Successfully parsed table with {len(df)} rows and {len(df.columns)} columns")
    return df

def save_table(df, base_filename):
    """Save the table as both CSV and Excel with formatting."""
    app_logger.debug(f"Saving table to {base_filename}")
    
    # Save as CSV file
    csv_filename = f"{base_filename}.csv"
    df.to_csv(csv_filename, index=False)
    
    # Save as Excel file with basic formatting
    excel_filename = f"{base_filename}.xlsx"
    
    with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Table', index=False)
        
        # Get the workbook and worksheet
        workbook = writer.book
        worksheet = writer.sheets['Table']
        
        # Auto-adjust column widths
        for column in worksheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            
            adjusted_width = min(max_length + 2, 50)  # Cap at 50 characters
            worksheet.column_dimensions[column_letter].width = adjusted_width
        
        # Apply basic formatting to headers
        from openpyxl.styles import Font, PatternFill
        header_font = Font(bold=True)
        header_fill = PatternFill(start_color="E6E6FA", end_color="E6E6FA", fill_type="solid")
        
        for cell in worksheet[1]:  # First row (headers)
            cell.font = header_font
            cell.fill = header_fill
    
    app_logger.info(f"Table saved as CSV: {csv_filename} and Excel: {excel_filename}")
    return csv_filename, excel_filename

def process_and_serialize(table_lines, output_dir, index):
    """Process a single table and return JSON-serializable data."""
    try:
        # Parse table with our improved parser
        df = parse_table(table_lines)
        
        if df.empty:
            return None
            
        # Save table files
        base_filename = os.path.join(output_dir, f"formatted_table_{index+1}")
        csv_file, excel_file = save_table(df, base_filename)
        
        # Convert DataFrame to JSON-serializable format
        table_data = {
            'columns': df.columns.tolist(),
            'data': df.to_dict('records'),
            'csv_file': csv_file,
            'excel_file': excel_file
        }
        
        app_logger.info(f"Successfully processed table {index+1}")
        return table_data
        
    except Exception as e:
        app_logger.error(f"Error processing table {index+1}: {e}")
        return None

