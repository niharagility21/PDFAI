#!/usr/bin/env python
# flask_pdf_extractor_app.py - Enhanced Forensic Analysis Frontend
# Complete Flask frontend for PDF table extraction and comprehensive forensic analysis
# requirements: flask, mistralai==1.5.1, pandas==2.0.0, openpyxl==3.1.2, PyPDF2==3.0.1, Pillow==10.0.0, lxml==4.9.3

from flask import Flask, render_template_string, request, jsonify, send_file, flash, redirect, url_for
import os
import json
import re
import pandas as pd
import numpy as np
from mistralai import Mistral
import PyPDF2
import datetime
import traceback
import tempfile
import zipfile
from werkzeug.utils import secure_filename
import uuid
import threading
import time
import hashlib
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
import io

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    print("Warning: Pillow not available. Image analysis will be limited.")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    print("Warning: python-magic not available. File type detection will be limited.")

# Hardcoded API key
MISTRAL_API_KEY = "fvrbS59yLn1aZi0EhyAeUdupJy8AIuaR"

def clean_number(text):
    """Clean and format numeric values"""
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
    """Extract tables from markdown text"""
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
        
    return tables

def parse_table(table_lines):
    """Parse table lines with improved formatting"""
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
    
    return df

def save_table(df, base_filename):
    """Save the table as both CSV and Excel with formatting"""
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
    
    return csv_filename, excel_filename

def analyze_xmp_metadata(xmp_info):
    """Detailed XMP metadata analysis for forensic purposes"""
    xmp_analysis = {
        'software_used': [],
        'modification_history': [],
        'creation_tools': [],
        'editing_sessions': [],
        'suspicious_patterns': []
    }
    
    if not xmp_info:
        return xmp_analysis
    
    try:
        xmp_str = str(xmp_info)
        
        # Parse XMP as XML if possible
        try:
            # Remove namespace prefixes for easier parsing
            clean_xmp = re.sub(r'xmlns[^=]*="[^"]*"', '', xmp_str)
            clean_xmp = re.sub(r'[a-zA-Z]+:', '', clean_xmp)
            
            root = ET.fromstring(clean_xmp)
            
            # Extract detailed software information
            software_patterns = {
                'Adobe Photoshop': r'photoshop|ps:|adobe:photoshop',
                'Adobe Acrobat': r'acrobat|pdf:|adobe:acrobat',
                'Adobe InDesign': r'indesign|adobe:indesign',
                'Microsoft Word': r'microsoft\s+word|word|winword',
                'LibreOffice': r'libreoffice|openoffice',
                'Google Docs': r'google\s+docs|docs\.google',
                'Canva': r'canva',
                'PDF Editors': r'foxit|nitro|pdfcreator|pdfelement|smallpdf'
            }
            
            for software, pattern in software_patterns.items():
                if re.search(pattern, xmp_str, re.IGNORECASE):
                    xmp_analysis['software_used'].append(software)
            
            # Look for modification dates and sequences
            date_fields = ['ModifyDate', 'MetadataDate', 'CreateDate', 'modifyDate', 'createDate']
            modification_dates = []
            
            for elem in root.iter():
                if elem.tag and any(date_field.lower() in elem.tag.lower() for date_field in date_fields):
                    if elem.text:
                        modification_dates.append({
                            'field': elem.tag,
                            'value': elem.text,
                            'timestamp': elem.text
                        })
            
            # Analyze modification patterns
            if len(modification_dates) > 2:
                xmp_analysis['suspicious_patterns'].append(f"Multiple modification timestamps found ({len(modification_dates)})")
            
        except ET.ParseError:
            # Fallback to regex parsing if XML parsing fails
            software_mentions = re.findall(r'(?:creator|producer|application)["\']?\s*[:=]\s*["\']?([^"\'>\n]+)', xmp_str, re.IGNORECASE)
            xmp_analysis['software_used'].extend(software_mentions)
            
    except Exception as e:
        xmp_analysis['suspicious_patterns'].append(f"XMP parsing error: {str(e)}")
    
    return xmp_analysis

def analyze_pdf_objects(pdf_path):
    """Analyze PDF object structure for signs of modification"""
    object_analysis = {
        'total_objects': 0,
        'suspicious_objects': [],
        'object_types': Counter(),
        'potential_modifications': [],
        'embedded_files': [],
        'suspicious_references': []
    }
    
    try:
        with open(pdf_path, 'rb') as file:
            content = file.read()
        
        # Find all PDF objects
        object_pattern = r'(\d+)\s+(\d+)\s+obj'
        objects = re.findall(object_pattern, content.decode('latin-1', errors='ignore'))
        object_analysis['total_objects'] = len(objects)
        
        # Look for suspicious object patterns
        suspicious_patterns = [
            (r'/JavaScript', 'JavaScript code found'),
            (r'/JS', 'JavaScript code found'),
            (r'/EmbeddedFile', 'Embedded file detected'),
            (r'/FileAttachment', 'File attachment found'),
            (r'/GoToR', 'External reference found'),
            (r'/Launch', 'Launch action found'),
            (r'/Form', 'Form fields present'),
            (r'/Annot', 'Annotation found')
        ]
        
        content_str = content.decode('latin-1', errors='ignore')
        for pattern, description in suspicious_patterns:
            matches = re.findall(pattern, content_str, re.IGNORECASE)
            if matches:
                object_analysis['suspicious_objects'].append(f"{description} ({len(matches)} instances)")
        
        # Analyze cross-reference table
        xref_pattern = r'xref\s*\n.*?trailer'
        xref_matches = re.findall(xref_pattern, content_str, re.DOTALL)
        if len(xref_matches) > 1:
            object_analysis['potential_modifications'].append(f"Multiple cross-reference tables found ({len(xref_matches)})")
        
        # Look for incremental updates
        eof_count = content.count(b'%%EOF')
        if eof_count > 1:
            object_analysis['potential_modifications'].append(f"Document has {eof_count-1} incremental updates")
        
        # Check for object streams (can hide modifications)
        obj_stream_count = len(re.findall(r'/ObjStm', content_str, re.IGNORECASE))
        if obj_stream_count > 0:
            object_analysis['suspicious_objects'].append(f"Object streams found ({obj_stream_count}) - can hide object modifications")
        
    except Exception as e:
        object_analysis['potential_modifications'].append(f"Object analysis error: {str(e)}")
    
    return object_analysis

def analyze_fonts(pdf):
    """Analyze fonts used in the PDF for inconsistencies"""
    font_analysis = {
        'fonts_used': {},
        'font_inconsistencies': [],
        'embedded_fonts': 0,
        'system_fonts': 0,
        'suspicious_patterns': []
    }
    
    try:
        fonts_found = set()
        
        for page_num, page in enumerate(pdf.pages):
            try:
                if '/Font' in page:
                    font_dict = page['/Font']
                    for font_name, font_obj in font_dict.items():
                        try:
                            font_data = font_obj.get_object()
                            if '/BaseFont' in font_data:
                                base_font = font_data['/BaseFont']
                                fonts_found.add(str(base_font))
                                
                                # Check if font is embedded
                                if '/FontDescriptor' in font_data:
                                    font_desc = font_data['/FontDescriptor'].get_object()
                                    if '/FontFile' in font_desc or '/FontFile2' in font_desc or '/FontFile3' in font_desc:
                                        font_analysis['embedded_fonts'] += 1
                                    else:
                                        font_analysis['system_fonts'] += 1
                        except:
                            continue
            except:
                continue
        
        font_analysis['fonts_used'] = list(fonts_found)
        
        # Analyze font patterns
        if len(fonts_found) > 10:
            font_analysis['suspicious_patterns'].append(f"Unusually high number of fonts ({len(fonts_found)})")
        
        # Check for mix of embedded and system fonts
        if font_analysis['embedded_fonts'] > 0 and font_analysis['system_fonts'] > 0:
            font_analysis['font_inconsistencies'].append("Mix of embedded and system fonts - possible text replacement")
        
        # Look for common editing software fonts
        editing_fonts = ['Arial', 'Helvetica', 'Times', 'Courier', 'Calibri']
        common_fonts_used = [f for f in fonts_found if any(ef in str(f) for ef in editing_fonts)]
        if len(common_fonts_used) > 0 and len(fonts_found) > len(common_fonts_used):
            font_analysis['suspicious_patterns'].append("Mix of standard and non-standard fonts detected")
        
    except Exception as e:
        font_analysis['suspicious_patterns'].append(f"Font analysis error: {str(e)}")
    
    return font_analysis

def analyze_images(pdf, pdf_path):
    """Analyze images in the PDF for modifications"""
    image_analysis = {
        'total_images': 0,
        'image_details': [],
        'suspicious_patterns': [],
        'compression_inconsistencies': [],
        'metadata_findings': []
    }
    
    if not PILLOW_AVAILABLE:
        image_analysis['suspicious_patterns'].append("Image analysis limited - Pillow not available")
        return image_analysis
    
    try:
        for page_num, page in enumerate(pdf.pages):
            try:
                if '/XObject' in page['/Resources']:
                    xobject = page['/Resources']['/XObject'].get_object()
                    
                    for obj_name, obj in xobject.items():
                        try:
                            obj_data = obj.get_object()
                            if obj_data.get('/Subtype') == '/Image':
                                image_analysis['total_images'] += 1
                                
                                image_info = {
                                    'page': page_num + 1,
                                    'name': obj_name,
                                    'width': obj_data.get('/Width', 'Unknown'),
                                    'height': obj_data.get('/Height', 'Unknown'),
                                    'bits_per_component': obj_data.get('/BitsPerComponent', 'Unknown'),
                                    'color_space': str(obj_data.get('/ColorSpace', 'Unknown')),
                                    'filter': str(obj_data.get('/Filter', 'Unknown'))
                                }
                                
                                # Analyze image data if available
                                try:
                                    image_data = obj_data._data
                                    if image_data:
                                        # Try to extract and analyze the image
                                        try:
                                            # Handle different compression formats
                                            if '/DCTDecode' in str(obj_data.get('/Filter', '')):
                                                # JPEG image
                                                img = Image.open(io.BytesIO(image_data))
                                                
                                                # Check EXIF data
                                                if hasattr(img, '_getexif') and img._getexif():
                                                    exif_data = img._getexif()
                                                    if exif_data:
                                                        for tag_id, value in exif_data.items():
                                                            tag = TAGS.get(tag_id, tag_id)
                                                            if tag in ['Software', 'DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
                                                                image_analysis['metadata_findings'].append(f"Image {obj_name}: {tag} = {value}")
                                                
                                                image_info['format'] = 'JPEG'
                                                image_info['exif_present'] = bool(img._getexif())
                                            
                                            elif '/FlateDecode' in str(obj_data.get('/Filter', '')):
                                                image_info['format'] = 'PNG/Compressed'
                                            else:
                                                image_info['format'] = 'Other'
                                                
                                        except Exception as img_error:
                                            image_info['analysis_error'] = str(img_error)
                                            
                                except Exception as data_error:
                                    image_info['data_error'] = str(data_error)
                                
                                image_analysis['image_details'].append(image_info)
                                
                        except Exception as obj_error:
                            continue
                            
            except Exception as page_error:
                continue
        
        # Analyze patterns
        if image_analysis['total_images'] > 0:
            formats = [img.get('format', 'Unknown') for img in image_analysis['image_details']]
            format_counts = Counter(formats)
            
            if len(format_counts) > 1:
                image_analysis['compression_inconsistencies'].append(f"Multiple image formats found: {dict(format_counts)}")
            
            # Check for resolution inconsistencies
            resolutions = []
            for img in image_analysis['image_details']:
                if img.get('width') != 'Unknown' and img.get('height') != 'Unknown':
                    try:
                        res = int(img['width']) * int(img['height'])
                        resolutions.append(res)
                    except:
                        continue
            
            if resolutions and (max(resolutions) / min(resolutions)) > 100:
                image_analysis['suspicious_patterns'].append("Significant resolution differences between images")
        
    except Exception as e:
        image_analysis['suspicious_patterns'].append(f"Image analysis error: {str(e)}")
    
    return image_analysis

def calculate_file_hash(filepath):
    """Calculate file hash for integrity verification"""
    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()
    
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha256.update(chunk)
        
        return {
            'md5': hash_md5.hexdigest(),
            'sha256': hash_sha256.hexdigest()
        }
    except Exception as e:
        return {'error': str(e)}

def extract_pdf_metadata(pdf_path):
    """Extract comprehensive metadata from PDF for detailed forensic analysis"""
    print("\n=== COMPREHENSIVE PDF FORENSIC ANALYSIS ===\n")
    
    metadata_results = {
        'basic_info': {},
        'security_info': {},
        'forensic_indicators': [],
        'risk_assessment': 'Low',
        'recommendations': [],
        'detailed_analysis': {
            'xmp_analysis': {},
            'object_analysis': {},
            'font_analysis': {},
            'image_analysis': {},
            'file_integrity': {}
        },
        'modification_timeline': [],
        'editing_software_detected': [],
        'suspicious_behaviors': []
    }
    
    try:
        # File integrity check
        print("1. Calculating file integrity hashes...")
        metadata_results['detailed_analysis']['file_integrity'] = calculate_file_hash(pdf_path)
        
        with open(pdf_path, 'rb') as file:
            pdf = PyPDF2.PdfReader(file)
            
            # Basic document information
            print("2. Extracting basic document information...")
            info = pdf.metadata
            if info:
                print("Document Information Dictionary:")
                print("-" * 50)
                
                metadata_fields = [
                    ('Title', '/Title'),
                    ('Author', '/Author'),
                    ('Subject', '/Subject'),
                    ('Keywords', '/Keywords'),
                    ('Creator', '/Creator'),
                    ('Producer', '/Producer'),
                    ('Creation Date', '/CreationDate'),
                    ('Modification Date', '/ModDate')
                ]
                
                for label, key in metadata_fields:
                    value = info.get(key, "Not available")
                    
                    # Enhanced date parsing
                    if key in ['/CreationDate', '/ModDate'] and value != "Not available":
                        try:
                            date_str = str(value)
                            if date_str.startswith("D:"):
                                date_str = date_str[2:]
                                
                                if len(date_str) >= 8:
                                    year = int(date_str[0:4])
                                    month = int(date_str[4:6])
                                    day = int(date_str[6:8])
                                    
                                    time_str = ""
                                    if len(date_str) >= 14:
                                        hour = int(date_str[8:10])
                                        minute = int(date_str[10:12])
                                        second = int(date_str[12:14])
                                        time_str = f"{hour:02d}:{minute:02d}:{second:02d}"
                                    
                                    formatted_date = f"{year}-{month:02d}-{day:02d}"
                                    if time_str:
                                        formatted_date += f" {time_str}"
                                        
                                    if len(date_str) > 14:
                                        tz_match = re.search(r'([+-])(\d{2})\'?(\d{2})\'?', date_str[14:])
                                        if tz_match:
                                            tz_sign, tz_hours, tz_minutes = tz_match.groups()
                                            formatted_date += f" UTC{tz_sign}{tz_hours}:{tz_minutes}"
                                    
                                    value = formatted_date
                                    
                                    # Add to modification timeline
                                    if key == '/CreationDate':
                                        metadata_results['modification_timeline'].append({
                                            'event': 'Document Created',
                                            'timestamp': formatted_date,
                                            'source': 'PDF Metadata'
                                        })
                                        # Store creation date for comparison
                                        metadata_results['_creation_date'] = formatted_date
                                    elif key == '/ModDate':
                                        metadata_results['modification_timeline'].append({
                                            'event': 'Document Modified',
                                            'timestamp': formatted_date,
                                            'source': 'PDF Metadata'
                                        })
                                        # Store modification date for comparison
                                        metadata_results['_modification_date'] = formatted_date
                        except Exception as date_error:
                            print(f"Date parsing error for {key}: {date_error}")
                    
                    print(f"{label}: {value}")
                    metadata_results['basic_info'][label] = str(value) if value is not None else "Not available"
                    
                    # Track editing software
                    if key in ['/Creator', '/Producer'] and value != "Not available":
                        software = str(value).lower()
                        if any(editor in software for editor in ['photoshop', 'acrobat', 'word', 'libreoffice', 'canva', 'foxit']):
                            metadata_results['editing_software_detected'].append(f"{label}: {value}")
            
            # Enhanced XMP metadata analysis
            print("\n3. Performing detailed XMP metadata analysis...")
            try:
                xmp_info = pdf.xmp_metadata
                metadata_results['detailed_analysis']['xmp_analysis'] = analyze_xmp_metadata(xmp_info)
                
                if metadata_results['detailed_analysis']['xmp_analysis']['software_used']:
                    print("Software detected in XMP:")
                    for software in metadata_results['detailed_analysis']['xmp_analysis']['software_used']:
                        print(f"  - {software}")
                        metadata_results['editing_software_detected'].append(f"XMP: {software}")
                
                if metadata_results['detailed_analysis']['xmp_analysis']['modification_history']:
                    print("Modification history found:")
                    for mod in metadata_results['detailed_analysis']['xmp_analysis']['modification_history']:
                        print(f"  - {mod}")
                        metadata_results['modification_timeline'].append({
                            'event': 'XMP Modification Record',
                            'details': mod,
                            'source': 'XMP Metadata'
                        })
                
            except Exception as xmp_error:
                print(f"XMP analysis error: {xmp_error}")
                metadata_results['detailed_analysis']['xmp_analysis'] = {'error': str(xmp_error)}
            
            # PDF object structure analysis
            print("\n4. Analyzing PDF object structure...")
            metadata_results['detailed_analysis']['object_analysis'] = analyze_pdf_objects(pdf_path)
            
            if metadata_results['detailed_analysis']['object_analysis']['suspicious_objects']:
                print("Suspicious objects found:")
                for obj in metadata_results['detailed_analysis']['object_analysis']['suspicious_objects']:
                    print(f"  - {obj}")
                    metadata_results['suspicious_behaviors'].append(obj)
            
            # Font analysis
            print("\n5. Analyzing fonts and typography...")
            metadata_results['detailed_analysis']['font_analysis'] = analyze_fonts(pdf)
            
            if metadata_results['detailed_analysis']['font_analysis']['font_inconsistencies']:
                print("Font inconsistencies detected:")
                for inconsistency in metadata_results['detailed_analysis']['font_analysis']['font_inconsistencies']:
                    print(f"  - {inconsistency}")
                    metadata_results['suspicious_behaviors'].append(f"Font: {inconsistency}")
            
            # Image analysis
            print("\n6. Analyzing embedded images...")
            metadata_results['detailed_analysis']['image_analysis'] = analyze_images(pdf, pdf_path)
            
            if metadata_results['detailed_analysis']['image_analysis']['total_images'] > 0:
                print(f"Found {metadata_results['detailed_analysis']['image_analysis']['total_images']} images")
                
                if metadata_results['detailed_analysis']['image_analysis']['metadata_findings']:
                    print("Image metadata found:")
                    for finding in metadata_results['detailed_analysis']['image_analysis']['metadata_findings']:
                        print(f"  - {finding}")
                        metadata_results['modification_timeline'].append({
                            'event': 'Image Metadata',
                            'details': finding,
                            'source': 'Image EXIF'
                        })
            
            # Security analysis
            print("\n7. Performing security analysis...")
            metadata_results['security_info']['encrypted'] = pdf.is_encrypted
            if pdf.is_encrypted:
                print("ALERT: Document is encrypted")
                metadata_results['forensic_indicators'].append("Document is encrypted - can hide editing history")
            else:
                print("Document is not encrypted")
            
            # Check for incremental updates and revisions
            print("\n8. Analyzing document revisions...")
            try:
                with open(pdf_path, 'rb') as f:
                    content = f.read()
                    eof_count = content.count(b"%%EOF")
                    metadata_results['security_info']['revisions'] = eof_count - 1
                    
                    if eof_count > 1:
                        print(f"WARNING: Found {eof_count} EOF markers - indicates {eof_count-1} document revisions")
                        metadata_results['forensic_indicators'].append(f"Document revised {eof_count-1} times")
                        metadata_results['modification_timeline'].append({
                            'event': f'Document Revisions Detected ({eof_count-1})',
                            'details': 'Incremental updates found',
                            'source': 'PDF Structure'
                        })
                    else:
                        print("No incremental updates detected")
            except Exception as rev_error:
                print(f"Revision analysis error: {rev_error}")
            
            # Page analysis
            page_count = len(pdf.pages)
            print(f"\n9. Document contains {page_count} pages")
            metadata_results['basic_info']['Page Count'] = str(page_count)
            
            # Check for post-creation editing by comparing dates
            print("\n9.5. Analyzing creation vs modification timestamps...")
            if '_creation_date' in metadata_results and '_modification_date' in metadata_results:
                try:
                    creation_date = metadata_results['_creation_date']
                    modification_date = metadata_results['_modification_date']
                    
                    # Parse dates for comparison (basic string comparison should work for ISO format)
                    if creation_date != modification_date:
                        print(f"ALERT: Document was edited after creation!")
                        print(f"  Created: {creation_date}")
                        print(f"  Modified: {modification_date}")
                        metadata_results['forensic_indicators'].append(f"Document edited after creation - Created: {creation_date}, Modified: {modification_date}")
                        metadata_results['suspicious_behaviors'].append(f"Post-creation editing detected: {creation_date} → {modification_date}")
                        metadata_results['modification_timeline'].append({
                            'event': 'Post-Creation Editing Detected',
                            'details': f"Document was modified after initial creation ({creation_date} → {modification_date})",
                            'source': 'Timeline Analysis'
                        })
                    else:
                        print(f"No post-creation editing detected (same timestamp: {creation_date})")
                except Exception as date_compare_error:
                    print(f"Error comparing creation/modification dates: {date_compare_error}")
            
            # Clean up temporary date fields
            if '_creation_date' in metadata_results:
                del metadata_results['_creation_date']
            if '_modification_date' in metadata_results:
                del metadata_results['_modification_date']
            
            # Risk assessment
            print("\n10. Performing comprehensive risk assessment...")
            risk_score = 0
            risk_factors = []
            
            if pdf.is_encrypted:
                risk_score += 3
                risk_factors.append("Document encryption")
            
            if metadata_results['security_info']['revisions'] > 0:
                risk_score += 2 * metadata_results['security_info']['revisions']
                risk_factors.append(f"Multiple revisions ({metadata_results['security_info']['revisions']})")
            
            if len(metadata_results['editing_software_detected']) > 2:
                risk_score += 2
                risk_factors.append("Multiple editing software detected")
            
            if metadata_results['detailed_analysis']['object_analysis']['suspicious_objects']:
                risk_score += len(metadata_results['detailed_analysis']['object_analysis']['suspicious_objects'])
                risk_factors.append("Suspicious PDF objects found")
            
            if metadata_results['detailed_analysis']['font_analysis']['font_inconsistencies']:
                risk_score += 1
                risk_factors.append("Font inconsistencies detected")
            
            if metadata_results['detailed_analysis']['image_analysis']['compression_inconsistencies']:
                risk_score += 1
                risk_factors.append("Image compression inconsistencies")
            
            # Check for post-creation editing
            post_creation_editing = any('Post-creation editing detected' in str(behavior) for behavior in metadata_results.get('suspicious_behaviors', []))
            if post_creation_editing:
                risk_score += 3
                risk_factors.append("Document edited after creation")
            
            # Determine risk level
            if risk_score >= 8:
                metadata_results['risk_assessment'] = 'High'
                metadata_results['recommendations'].extend([
                    "Document shows multiple signs of modification",
                    "Perform thorough verification with original source",
                    "Consider professional forensic analysis",
                    "Do not rely on this document for critical decisions"
                ])
            elif risk_score >= 4:
                metadata_results['risk_assessment'] = 'Medium'
                metadata_results['recommendations'].extend([
                    "Some suspicious indicators detected",
                    "Cross-verify information with alternative sources",
                    "Exercise caution when using this document"
                ])
            else:
                metadata_results['risk_assessment'] = 'Low'
                metadata_results['recommendations'].append("No major risk indicators detected")
            
            # Store risk score for frontend display
            metadata_results['risk_score'] = f"{risk_score}/10"
            
            # Final summary
            print("\n" + "="*70)
            print("COMPREHENSIVE FORENSIC ANALYSIS SUMMARY")
            print("="*70)
            print(f"Risk Level: {metadata_results['risk_assessment']}")
            print(f"Risk Score: {risk_score}/10")
            
            if risk_factors:
                print("\nRisk Factors:")
                for factor in risk_factors:
                    print(f"  - {factor}")
            
            if metadata_results['editing_software_detected']:
                print("\nEditing Software Detected:")
                for software in set(metadata_results['editing_software_detected']):
                    print(f"  - {software}")
            
            if metadata_results['modification_timeline']:
                print(f"\nModification Timeline ({len(metadata_results['modification_timeline'])} events):")
                for event in metadata_results['modification_timeline'][-5:]:  # Show last 5 events
                    print(f"  - {event.get('event', 'Unknown')}: {event.get('details', event.get('timestamp', 'No details'))}")
            
            print("\nRecommendations:")
            for rec in metadata_results['recommendations']:
                print(f"  - {rec}")
            
    except Exception as e:
        metadata_results['error'] = str(e)
        print(f"Error in comprehensive forensic analysis: {str(e)}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70 + "\n")
    
    # Ensure all values are JSON serializable
    def make_serializable(obj):
        if isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [make_serializable(item) for item in obj]
        elif isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return str(obj)
        else:
            return obj
    
    metadata_results = make_serializable(metadata_results)
    
    print(f"DEBUG: Comprehensive forensic analysis complete. Returning metadata with {len(metadata_results)} main sections")
    return metadata_results

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a random secret key
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Global storage for processing results
processing_results = {}

# Enhanced HTML Template with better UI
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PDF Forensic Analyzer Pro</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --secondary: #64748b;
            --accent: #f59e0b;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --light: #f8fafc;
            --medium: #e2e8f0;
            --dark: #0f172a;
            --border-radius: 16px;
            --border-radius-sm: 8px;
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
            --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-dark: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background: var(--gradient-primary);
            min-height: 100vh;
            color: var(--dark);
            line-height: 1.6;
            font-size: 14px;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .main-card {
            background: white;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-xl);
            overflow: hidden;
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .header {
            background: var(--gradient-dark);
            color: white;
            padding: 3rem 2rem;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at 50% 50%, rgba(255,255,255,0.1) 0%, transparent 50%);
        }
        
        .header-content {
            position: relative;
            z-index: 2;
        }
        
        .header h1 {
            font-size: 3rem;
            font-weight: 800;
            margin-bottom: 1rem;
            letter-spacing: -0.025em;
            background: linear-gradient(135deg, #fff 0%, #e2e8f0 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .header .subtitle {
            font-size: 1.125rem;
            opacity: 0.9;
            font-weight: 400;
            max-width: 600px;
            margin: 0 auto;
        }
        
        .content {
            padding: 2rem;
        }
        
        .upload-section {
            background: linear-gradient(135deg, var(--light) 0%, #fff 100%);
            border-radius: var(--border-radius);
            padding: 3rem;
            margin-bottom: 2rem;
            border: 2px dashed var(--medium);
            text-align: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .upload-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, transparent 49%, rgba(37, 99, 235, 0.02) 50%, transparent 51%);
            pointer-events: none;
        }
        
        .upload-section:hover {
            border-color: var(--primary);
            background: white;
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }
        
        .upload-section h2 {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            color: var(--dark);
        }
        
        .upload-section p {
            color: var(--secondary);
            margin-bottom: 2rem;
            font-size: 1rem;
        }
        
        .upload-icon {
            font-size: 3rem;
            color: var(--primary);
            margin-bottom: 1rem;
            opacity: 0.6;
        }
        
        .file-input-wrapper {
            position: relative;
            display: inline-block;
            margin-bottom: 1.5rem;
        }
        
        .file-input {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        
        .file-input-button {
            display: inline-flex;
            align-items: center;
            gap: 0.75rem;
            padding: 1rem 2rem;
            background: white;
            border: 2px solid var(--medium);
            border-radius: var(--border-radius-sm);
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--secondary);
            cursor: pointer;
            transition: all 0.3s ease;
            min-width: 200px;
        }
        
        .file-input-button:hover {
            border-color: var(--primary);
            color: var(--primary);
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }
        
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: var(--primary);
            color: white;
            border: none;
            padding: 1rem 2rem;
            font-size: 0.875rem;
            font-weight: 600;
            border-radius: var(--border-radius-sm);
            cursor: pointer;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none;
            position: relative;
            overflow: hidden;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(45deg, transparent 30%, rgba(255,255,255,0.1) 50%, transparent 70%);
            transform: translateX(-100%);
            transition: transform 0.6s;
        }
        
        .btn:hover::before {
            transform: translateX(100%);
        }
        
        .btn:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        .btn:disabled {
            background: var(--secondary);
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .btn-accent {
            background: var(--accent);
        }
        
        .btn-accent:hover {
            background: #d97706;
        }
        
        .btn-success {
            background: var(--success);
        }
        
        .btn-success:hover {
            background: #059669;
        }
        
        .progress-container {
            margin: 2rem 0;
            display: none;
        }
        
        .progress-bar {
            width: 100%;
            height: 6px;
            background: var(--medium);
            border-radius: 3px;
            overflow: hidden;
            position: relative;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--primary), var(--accent));
            width: 0%;
            transition: width 0.5s ease;
            position: relative;
        }
        
        .progress-fill::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent);
            animation: shimmer 2s infinite;
        }
        
        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }
        
        .progress-text {
            text-align: center;
            margin-top: 1rem;
            font-weight: 500;
            color: var(--secondary);
            font-size: 0.875rem;
        }
        
        .results-section {
            margin-top: 2rem;
            display: none;
        }
        
        .tab-container {
            background: white;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow-md);
            overflow: hidden;
            border: 1px solid var(--medium);
        }
        
        .tab-buttons {
            display: flex;
            background: var(--light);
            border-bottom: 1px solid var(--medium);
            overflow-x: auto;
            scrollbar-width: none;
            -ms-overflow-style: none;
        }
        
        .tab-buttons::-webkit-scrollbar {
            display: none;
        }
        
        .tab-button {
            flex: 1;
            background: none;
            border: none;
            padding: 1rem 1.5rem;
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            white-space: nowrap;
            min-width: 120px;
            color: var(--secondary);
            text-transform: uppercase;
            letter-spacing: 0.025em;
            position: relative;
        }
        
        .tab-button::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--primary);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }
        
        .tab-button:hover {
            background: rgba(37, 99, 235, 0.05);
            color: var(--primary);
        }
        
        .tab-button.active {
            background: white;
            color: var(--primary);
        }
        
        .tab-button.active::after {
            transform: scaleX(1);
        }
        
        .tab-content {
            display: none;
            padding: 2rem;
            min-height: 400px;
            max-height: 800px;
            overflow-y: auto;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: linear-gradient(135deg, white 0%, var(--light) 100%);
            padding: 1.5rem;
            border-radius: var(--border-radius-sm);
            text-align: center;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--medium);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: var(--primary);
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-lg);
        }
        
        .stat-number {
            font-size: 2rem;
            font-weight: 800;
            color: var(--primary);
            line-height: 1;
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            color: var(--secondary);
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .risk-assessment {
            margin: 2rem 0;
            padding: 2rem;
            border-radius: var(--border-radius);
            font-weight: 700;
            text-align: center;
            font-size: 1.125rem;
            position: relative;
            overflow: hidden;
        }
        
        .risk-assessment::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            opacity: 0.1;
            background: repeating-linear-gradient(
                45deg,
                transparent,
                transparent 10px,
                currentColor 10px,
                currentColor 20px
            );
        }
        
        .risk-low {
            background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
            color: #166534;
            border: 2px solid #bbf7d0;
        }
        
        .risk-medium {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            color: #92400e;
            border: 2px solid #fde68a;
        }
        
        .risk-high {
            background: linear-gradient(135deg, #fecaca 0%, #fca5a5 100%);
            color: #991b1b;
            border: 2px solid #fca5a5;
        }
        
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .metadata-card {
            background: white;
            border-radius: var(--border-radius-sm);
            padding: 1.5rem;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--medium);
            border-left: 4px solid var(--primary);
        }
        
        .metadata-card h3 {
            color: var(--dark);
            margin-bottom: 1rem;
            font-size: 1.125rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .metadata-item {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--light);
            gap: 1rem;
        }
        
        .metadata-item:last-child {
            border-bottom: none;
        }
        
        .metadata-label {
            font-weight: 600;
            color: var(--secondary);
            flex-shrink: 0;
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.025em;
        }
        
        .metadata-value {
            color: var(--dark);
            text-align: right;
            word-wrap: break-word;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.8rem;
            background: var(--light);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }
        
        .analysis-section {
            margin-bottom: 2rem;
        }
        
        .analysis-section h4 {
            color: var(--dark);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--light);
            font-size: 1rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .finding-item {
            background: linear-gradient(135deg, #dbeafe 0%, #e0f2fe 100%);
            border: 1px solid #bfdbfe;
            padding: 1rem;
            margin-bottom: 0.75rem;
            border-radius: var(--border-radius-sm);
            border-left: 4px solid #3b82f6;
            font-size: 0.875rem;
        }
        
        .suspicious-item {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            border: 1px solid #fcd34d;
            padding: 1rem;
            margin-bottom: 0.75rem;
            border-radius: var(--border-radius-sm);
            border-left: 4px solid var(--warning);
            font-size: 0.875rem;
        }
        
        .timeline-item {
            background: white;
            border-left: 4px solid var(--accent);
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-radius: var(--border-radius-sm);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--medium);
        }
        
        .timeline-event {
            font-weight: 700;
            color: var(--accent);
            font-size: 1rem;
            margin-bottom: 0.5rem;
        }
        
        .timeline-details {
            color: var(--secondary);
            line-height: 1.5;
            font-size: 0.875rem;
        }
        
        .table-container {
            overflow-x: auto;
            margin-bottom: 2rem;
            border-radius: var(--border-radius-sm);
            box-shadow: var(--shadow-md);
            border: 1px solid var(--medium);
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.8rem;
            background: white;
        }
        
        .data-table th {
            background: var(--gradient-dark);
            color: white;
            padding: 1rem 0.75rem;
            text-align: left;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.025em;
            font-size: 0.7rem;
        }
        
        .data-table td {
            padding: 0.75rem;
            border-bottom: 1px solid var(--light);
            vertical-align: top;
            font-size: 0.8rem;
        }
        
        .data-table tbody tr:nth-child(even) {
            background: rgba(248, 250, 252, 0.5);
        }
        
        .data-table tbody tr:hover {
            background: var(--light);
        }
        
        .text-content {
            background: var(--light);
            border: 1px solid var(--medium);
            border-radius: var(--border-radius-sm);
            padding: 1.5rem;
            max-height: 500px;
            overflow-y: auto;
            font-family: 'Monaco', 'Consolas', monospace;
            font-size: 0.8rem;
            line-height: 1.6;
            white-space: pre-wrap;
        }
        
        .download-section {
            background: linear-gradient(135deg, var(--light) 0%, white 100%);
            border-radius: var(--border-radius-sm);
            padding: 2rem;
            text-align: center;
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--medium);
        }
        
        .download-section h3 {
            color: var(--dark);
            margin-bottom: 1rem;
            font-size: 1.25rem;
            font-weight: 700;
        }
        
        .download-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
            flex-wrap: wrap;
            margin-top: 1.5rem;
        }
        
        .alert {
            padding: 1rem;
            border-radius: var(--border-radius-sm);
            margin-bottom: 1rem;
            font-weight: 500;
            font-size: 0.875rem;
            border: 1px solid;
        }
        
        .alert-success {
            background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
            color: #166534;
            border-color: #bbf7d0;
        }
        
        .alert-error {
            background: linear-gradient(135deg, #fecaca 0%, #fca5a5 100%);
            color: #991b1b;
            border-color: #fca5a5;
        }
        
        .alert-info {
            background: linear-gradient(135deg, #dbeafe 0%, #bfdbfe 100%);
            color: #1e40af;
            border-color: #bfdbfe;
        }
        
        .alert-warning {
            background: linear-gradient(135deg, #fef3c7 0%, #fde68a 100%);
            color: #92400e;
            border-color: #fde68a;
        }
        
        .loading-spinner {
            display: inline-block;
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255,255,255,.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
            margin-right: 0.5rem;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .icon {
            width: 1rem;
            height: 1rem;
            opacity: 0.8;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .header {
                padding: 2rem 1rem;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .content {
                padding: 1.5rem;
            }
            
            .upload-section {
                padding: 2rem 1rem;
            }
            
            .metadata-grid {
                grid-template-columns: 1fr;
            }
            
            .tab-buttons {
                flex-direction: column;
            }
            
            .tab-button {
                min-width: auto;
            }
            
            .download-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        /* Custom scrollbar */
        .tab-content::-webkit-scrollbar {
            width: 6px;
        }
        
        .tab-content::-webkit-scrollbar-track {
            background: var(--light);
        }
        
        .tab-content::-webkit-scrollbar-thumb {
            background: var(--medium);
            border-radius: 3px;
        }
        
        .tab-content::-webkit-scrollbar-thumb:hover {
            background: var(--secondary);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="main-card">
            <div class="header">
                <div class="header-content">
                    <h1><i class="fas fa-shield-alt"></i> PDF Forensic Analyzer Pro</h1>
                    <p class="subtitle">Advanced PDF forensic analysis with intelligent table extraction and security assessment</p>
                </div>
            </div>
            
            <div class="content">
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ 'error' if category == 'error' else 'success' }}">
                                <i class="fas fa-{{ 'exclamation-triangle' if category == 'error' else 'check-circle' }}"></i>
                                {{ message }}
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <div class="upload-section">
                    <div class="upload-icon">
                        <i class="fas fa-file-pdf"></i>
                    </div>
                    <h2>Upload PDF Document</h2>
                    <p>Select a PDF file for comprehensive forensic analysis and intelligent table extraction</p>
                    <form id="uploadForm" enctype="multipart/form-data">
                        <div class="file-input-wrapper">
                            <input type="file" id="pdfFile" name="file" accept=".pdf" required class="file-input">
                            <div class="file-input-button">
                                <i class="fas fa-upload"></i>
                                <span>Choose PDF File</span>
                            </div>
                        </div>
                        <br>
                        <button type="submit" class="btn btn-accent" id="processBtn">
                            <i class="fas fa-search"></i>
                            <span>Analyze Document</span>
                        </button>
                    </form>
                </div>
                
                <div class="progress-container" id="progressContainer">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <div class="progress-text" id="progressText">Processing...</div>
                </div>
                
                <div class="results-section" id="resultsSection">
                    <div class="tab-container">
                        <div class="tab-buttons">
                            <button class="tab-button active" onclick="showTab('analysis')">
                                <i class="fas fa-chart-line"></i> Comprehensive Analysis
                            </button>
                            <button class="tab-button" onclick="showTab('tables')">
                                <i class="fas fa-table"></i> Tables
                            </button>
                            <button class="tab-button" onclick="showTab('text')">
                                <i class="fas fa-file-alt"></i> Text
                            </button>
                            <button class="tab-button" onclick="showTab('downloads')">
                                <i class="fas fa-download"></i> Downloads
                            </button>
                        </div>
                        
                        <div id="analysis-tab" class="tab-content active">
                            <div id="analysisContent"></div>
                        </div>
                        
                        <div id="tables-tab" class="tab-content">
                            <div id="tablesContent"></div>
                        </div>
                        
                        <div id="text-tab" class="tab-content">
                            <h3><i class="fas fa-file-alt"></i> Extracted Text Content</h3>
                            <div id="textContent" class="text-content"></div>
                        </div>
                        
                        <div id="downloads-tab" class="tab-content">
                            <div class="download-section">
                                <h3><i class="fas fa-download"></i> Download Analysis Results</h3>
                                <p>Download the complete forensic analysis and extracted data</p>
                                <div class="download-buttons" id="downloadButtons"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentJobId = null;
        
        // Update file input display
        document.getElementById('pdfFile').addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name || 'Choose PDF File';
            const span = document.querySelector('.file-input-button span');
            span.textContent = fileName.length > 25 ? fileName.substring(0, 25) + '...' : fileName;
        });
        
        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
        }
        
        function updateProgress(percentage, text) {
            const progressContainer = document.getElementById('progressContainer');
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('progressText');
            
            progressContainer.style.display = 'block';
            progressFill.style.width = percentage + '%';
            progressText.textContent = text || 'Processing...';
        }
        
        function hideProgress() {
            document.getElementById('progressContainer').style.display = 'none';
        }
        
        function showResults() {
            document.getElementById('resultsSection').style.display = 'block';
        }
        
        function hideResults() {
            document.getElementById('resultsSection').style.display = 'none';
        }
        
        function displayComprehensiveAnalysis(metadata) {
            const content = document.getElementById('analysisContent');
            
            if (!metadata) {
                content.innerHTML = '<div class="alert alert-error"><i class="fas fa-exclamation-triangle"></i> No analysis data available</div>';
                return;
            }
            
            let html = '';
            
            // Risk Assessment Header
            if (metadata.risk_assessment) {
                const riskClass = 'risk-' + String(metadata.risk_assessment).toLowerCase();
                const riskIcon = metadata.risk_assessment === 'High' ? 'exclamation-triangle' : 
                              metadata.risk_assessment === 'Medium' ? 'exclamation-circle' : 'check-circle';
                html += `<div class="risk-assessment ${riskClass}">
                    <i class="fas fa-${riskIcon}"></i>
                    <h2>Risk Assessment: ${escapeHtml(metadata.risk_assessment)}</h2>
                    ${metadata.risk_score ? `<p>Risk Score: ${metadata.risk_score}</p>` : ''}
                </div>`;
            }
            
            // Statistics Grid
            html += '<div class="stats-grid">';
            
            const stats = [
                {
                    value: metadata.basic_info?.['Page Count'] || '0',
                    label: 'Pages',
                    icon: 'fas fa-file'
                },
                {
                    value: metadata.security_info?.revisions ?? '0',
                    label: 'Revisions',
                    icon: 'fas fa-history'
                },
                {
                    value: metadata.editing_software_detected?.length || '0',
                    label: 'Software',
                    icon: 'fas fa-tools'
                },
                {
                    value: metadata.modification_timeline?.length || '0',
                    label: 'Timeline Events',
                    icon: 'fas fa-clock'
                },
                {
                    value: metadata.detailed_analysis?.image_analysis?.total_images || '0',
                    label: 'Images',
                    icon: 'fas fa-image'
                },
                {
                    value: metadata.suspicious_behaviors?.length || '0',
                    label: 'Suspicious Items',
                    icon: 'fas fa-exclamation-triangle'
                }
            ];
            
            stats.forEach(stat => {
                html += `<div class="stat-card">
                    <div class="stat-number">${stat.value}</div>
                    <div class="stat-label"><i class="${stat.icon}"></i> ${stat.label}</div>
                </div>`;
            });
            
            html += '</div>';
            
            // Key Findings
            html += '<div class="analysis-section">';
            html += '<h4><i class="fas fa-search"></i> Key Findings</h4>';
            
            if (metadata.forensic_indicators && metadata.forensic_indicators.length > 0) {
                metadata.forensic_indicators.forEach(indicator => {
                    html += `<div class="finding-item"><i class="fas fa-exclamation-triangle"></i> ${escapeHtml(String(indicator))}</div>`;
                });
            } else {
                html += '<div class="finding-item"><i class="fas fa-check-circle"></i> No major forensic indicators detected</div>';
            }
            
            html += '</div>';
            
            // Document Information
            html += '<div class="metadata-grid">';
            
            // Basic Information Card
            html += '<div class="metadata-card">';
            html += '<h3><i class="fas fa-info-circle"></i> Document Information</h3>';
            if (metadata.basic_info && Object.keys(metadata.basic_info).length > 0) {
                for (const [key, value] of Object.entries(metadata.basic_info)) {
                    const displayValue = value === null || value === undefined || value === '' ? 'N/A' : value;
                    html += `<div class="metadata-item">
                        <span class="metadata-label">${escapeHtml(key)}:</span>
                        <span class="metadata-value">${escapeHtml(String(displayValue))}</span>
                    </div>`;
                }
            }
            html += '</div>';
            
            // Security Information Card
            html += '<div class="metadata-card">';
            html += '<h3><i class="fas fa-shield-alt"></i> Security Analysis</h3>';
            if (metadata.security_info) {
                const encryptIcon = metadata.security_info.encrypted ? 'fas fa-lock' : 'fas fa-lock-open';
                const encryptColor = metadata.security_info.encrypted ? 'color: var(--danger)' : 'color: var(--success)';
                html += `<div class="metadata-item">
                    <span class="metadata-label">Encrypted:</span>
                    <span class="metadata-value" style="${encryptColor}">
                        <i class="${encryptIcon}"></i> ${metadata.security_info.encrypted ? 'Yes' : 'No'}
                    </span>
                </div>`;
                html += `<div class="metadata-item">
                    <span class="metadata-label">Revisions:</span>
                    <span class="metadata-value">${metadata.security_info.revisions || 0}</span>
                </div>`;
            }
            html += '</div>';
            
            // File Integrity Card
            if (metadata.detailed_analysis && metadata.detailed_analysis.file_integrity) {
                html += '<div class="metadata-card">';
                html += '<h3><i class="fas fa-fingerprint"></i> File Integrity</h3>';
                const integrity = metadata.detailed_analysis.file_integrity;
                if (integrity.md5) {
                    html += `<div class="metadata-item">
                        <span class="metadata-label">MD5:</span>
                        <span class="metadata-value">${integrity.md5}</span>
                    </div>`;
                }
                if (integrity.sha256) {
                    html += `<div class="metadata-item">
                        <span class="metadata-label">SHA256:</span>
                        <span class="metadata-value">${integrity.sha256.substring(0, 32)}...</span>
                    </div>`;
                }
                html += '</div>';
            }
            
            html += '</div>';
            
            // Software Detection
            if (metadata.editing_software_detected && metadata.editing_software_detected.length > 0) {
                html += '<div class="analysis-section">';
                html += '<h4><i class="fas fa-tools"></i> Editing Software Detected</h4>';
                metadata.editing_software_detected.forEach(software => {
                    html += `<div class="finding-item"><i class="fas fa-desktop"></i> ${escapeHtml(String(software))}</div>`;
                });
                html += '</div>';
            }
            
            // Suspicious Behaviors
            if (metadata.suspicious_behaviors && metadata.suspicious_behaviors.length > 0) {
                html += '<div class="analysis-section">';
                html += '<h4><i class="fas fa-exclamation-triangle"></i> Suspicious Behaviors</h4>';
                metadata.suspicious_behaviors.forEach(behavior => {
                    html += `<div class="suspicious-item"><i class="fas fa-flag"></i> ${escapeHtml(String(behavior))}</div>`;
                });
                html += '</div>';
            }
            
            // Timeline
            if (metadata.modification_timeline && metadata.modification_timeline.length > 0) {
                html += '<div class="analysis-section">';
                html += '<h4><i class="fas fa-clock"></i> Document Modification Timeline</h4>';
                html += `<p class="alert alert-info"><i class="fas fa-calendar"></i> ${metadata.modification_timeline.length} events detected</p>`;
                
                metadata.modification_timeline.forEach(event => {
                    html += `<div class="timeline-item">
                        <div class="timeline-event">
                            <i class="fas fa-calendar-day"></i> ${escapeHtml(event.event || 'Unknown Event')}
                        </div>
                        <div class="timeline-details">
                            ${event.timestamp ? `<i class="fas fa-clock"></i> ${escapeHtml(event.timestamp)}` : ''}
                            ${event.details ? ` - ${escapeHtml(event.details)}` : ''}
                            ${event.source ? `<br><small><i class="fas fa-tag"></i> Source: ${escapeHtml(event.source)}</small>` : ''}
                        </div>
                    </div>`;
                });
                html += '</div>';
            }
            
            // Detailed Analysis
            if (metadata.detailed_analysis) {
                const detailed = metadata.detailed_analysis;
                
                // XMP Analysis
                if (detailed.xmp_analysis) {
                    html += '<div class="analysis-section">';
                    html += '<h4><i class="fas fa-code"></i> XMP Metadata Analysis</h4>';
                    
                    if (detailed.xmp_analysis.software_used && detailed.xmp_analysis.software_used.length > 0) {
                        html += '<h5><i class="fas fa-tools"></i> Software Found in XMP:</h5>';
                        detailed.xmp_analysis.software_used.forEach(software => {
                            html += `<div class="finding-item"><i class="fas fa-desktop"></i> ${escapeHtml(software)}</div>`;
                        });
                    }
                    
                    if (detailed.xmp_analysis.suspicious_patterns && detailed.xmp_analysis.suspicious_patterns.length > 0) {
                        html += '<h5><i class="fas fa-exclamation-triangle"></i> Suspicious XMP Patterns:</h5>';
                        detailed.xmp_analysis.suspicious_patterns.forEach(pattern => {
                            html += `<div class="suspicious-item"><i class="fas fa-flag"></i> ${escapeHtml(pattern)}</div>`;
                        });
                    }
                    
                    html += '</div>';
                }
                
                // Object Analysis
                if (detailed.object_analysis) {
                    html += '<div class="analysis-section">';
                    html += '<h4><i class="fas fa-cubes"></i> PDF Object Analysis</h4>';
                    html += `<p><i class="fas fa-cube"></i> Total Objects: ${detailed.object_analysis.total_objects || 0}</p>`;
                    
                    if (detailed.object_analysis.suspicious_objects && detailed.object_analysis.suspicious_objects.length > 0) {
                        html += '<h5><i class="fas fa-exclamation-triangle"></i> Suspicious Objects:</h5>';
                        detailed.object_analysis.suspicious_objects.forEach(obj => {
                            html += `<div class="suspicious-item"><i class="fas fa-bug"></i> ${escapeHtml(obj)}</div>`;
                        });
                    }
                    
                    if (detailed.object_analysis.potential_modifications && detailed.object_analysis.potential_modifications.length > 0) {
                        html += '<h5><i class="fas fa-edit"></i> Potential Modifications:</h5>';
                        detailed.object_analysis.potential_modifications.forEach(mod => {
                            html += `<div class="finding-item"><i class="fas fa-pencil-alt"></i> ${escapeHtml(mod)}</div>`;
                        });
                    }
                    
                    html += '</div>';
                }
                
                // Font Analysis
                if (detailed.font_analysis) {
                    html += '<div class="analysis-section">';
                    html += '<h4><i class="fas fa-font"></i> Font Analysis</h4>';
                    
                    if (detailed.font_analysis.fonts_used && detailed.font_analysis.fonts_used.length > 0) {
                        html += `<p><i class="fas fa-list"></i> Fonts Found: ${detailed.font_analysis.fonts_used.length}</p>`;
                        html += `<p><i class="fas fa-download"></i> Embedded Fonts: ${detailed.font_analysis.embedded_fonts || 0}</p>`;
                        html += `<p><i class="fas fa-desktop"></i> System Fonts: ${detailed.font_analysis.system_fonts || 0}</p>`;
                    }
                    
                    if (detailed.font_analysis.font_inconsistencies && detailed.font_analysis.font_inconsistencies.length > 0) {
                        html += '<h5><i class="fas fa-exclamation-triangle"></i> Font Inconsistencies:</h5>';
                        detailed.font_analysis.font_inconsistencies.forEach(inconsistency => {
                            html += `<div class="suspicious-item"><i class="fas fa-font"></i> ${escapeHtml(inconsistency)}</div>`;
                        });
                    }
                    
                    html += '</div>';
                }
                
                // Image Analysis
                if (detailed.image_analysis) {
                    html += '<div class="analysis-section">';
                    html += '<h4><i class="fas fa-image"></i> Image Analysis</h4>';
                    html += `<p><i class="fas fa-images"></i> Total Images: ${detailed.image_analysis.total_images || 0}</p>`;
                    
                    if (detailed.image_analysis.metadata_findings && detailed.image_analysis.metadata_findings.length > 0) {
                        html += '<h5><i class="fas fa-tags"></i> Image Metadata Found:</h5>';
                        detailed.image_analysis.metadata_findings.forEach(finding => {
                            html += `<div class="finding-item"><i class="fas fa-tag"></i> ${escapeHtml(finding)}</div>`;
                        });
                    }
                    
                    if (detailed.image_analysis.compression_inconsistencies && detailed.image_analysis.compression_inconsistencies.length > 0) {
                        html += '<h5><i class="fas fa-compress"></i> Compression Inconsistencies:</h5>';
                        detailed.image_analysis.compression_inconsistencies.forEach(inconsistency => {
                            html += `<div class="suspicious-item"><i class="fas fa-compress-alt"></i> ${escapeHtml(inconsistency)}</div>`;
                        });
                    }
                    
                    html += '</div>';
                }
            }
            
            // Recommendations
            if (metadata.recommendations && metadata.recommendations.length > 0) {
                html += '<div class="analysis-section">';
                html += '<h4><i class="fas fa-lightbulb"></i> Recommendations</h4>';
                metadata.recommendations.forEach(rec => {
                    html += `<div class="alert alert-info"><i class="fas fa-info-circle"></i> ${escapeHtml(String(rec))}</div>`;
                });
                html += '</div>';
            }
            
            content.innerHTML = html;
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function displayTables(tables) {
            const content = document.getElementById('tablesContent');
            
            if (!tables || tables.length === 0) {
                content.innerHTML = '<div class="alert alert-info"><i class="fas fa-info-circle"></i> No tables found in the document.</div>';
                return;
            }
            
            let html = `<h3><i class="fas fa-table"></i> Extracted Tables (${tables.length} found)</h3>`;
            
            tables.forEach((table, index) => {
                html += `<div class="table-container" style="margin-bottom: 2rem;">
                    <h4><i class="fas fa-list-alt"></i> Table ${index + 1}</h4>
                    <table class="data-table">
                        <thead><tr>`;
                
                // Add headers
                if (table.data && table.data.length > 0) {
                    table.columns.forEach(col => {
                        html += `<th>${escapeHtml(col)}</th>`;
                    });
                    html += '</tr></thead><tbody>';
                    
                    // Add data rows
                    table.data.forEach(row => {
                        html += '<tr>';
                        table.columns.forEach(col => {
                            html += `<td>${escapeHtml(row[col] || '')}</td>`;
                        });
                        html += '</tr>';
                    });
                }
                
                html += '</tbody></table></div>';
            });
            
            content.innerHTML = html;
        }
        
        function displayText(text) {
            const content = document.getElementById('textContent');
            content.textContent = text || 'No text content extracted.';
        }
        
        function displayDownloads(jobId) {
            const content = document.getElementById('downloadButtons');
            
            let html = `
                <a href="/download/${jobId}/all" class="btn btn-primary">
                    <i class="fas fa-archive"></i> Download All (ZIP)
                </a>
                <a href="/download/${jobId}/metadata" class="btn btn-accent">
                    <i class="fas fa-file-code"></i> Forensic Report (JSON)
                </a>
                <a href="/download/${jobId}/text" class="btn btn-success">
                    <i class="fas fa-file-alt"></i> Text Content (TXT)
                </a>
            `;
            
            content.innerHTML = html;
        }
        
        document.getElementById('uploadForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const fileInput = document.getElementById('pdfFile');
            const processBtn = document.getElementById('processBtn');
            
            if (!fileInput.files[0]) {
                alert('Please select a PDF file');
                return;
            }
            
            // Disable form and show progress
            processBtn.disabled = true;
            processBtn.innerHTML = '<span class="loading-spinner"></span><span>Analyzing...</span>';
            hideResults();
            updateProgress(0, 'Uploading file...');
            
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);
            
            try {
                // Upload and start processing
                const response = await fetch('/upload', {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (result.success) {
                    currentJobId = result.job_id;
                    updateProgress(20, 'File uploaded, starting forensic analysis...');
                    
                    // Start polling for results
                    pollResults(currentJobId);
                } else {
                    throw new Error(result.error || 'Upload failed');
                }
                
            } catch (error) {
                console.error('Error:', error);
                alert('Error: ' + error.message);
                hideProgress();
                processBtn.disabled = false;
                processBtn.innerHTML = '<i class="fas fa-search"></i><span>Analyze Document</span>';
            }
        });
        
        async function pollResults(jobId) {
            try {
                const response = await fetch(`/status/${jobId}`);
                const result = await response.json();
                
                console.log('Poll result:', result);
                
                if (result.status === 'completed') {
                    updateProgress(100, 'Analysis complete!');
                    setTimeout(() => {
                        hideProgress();
                        showResults();
                        
                        // Display results
                        console.log('Displaying results...');
                        
                        if (result.metadata) {
                            console.log('Metadata found:', result.metadata);
                            displayComprehensiveAnalysis(result.metadata);
                        } else {
                            console.log('No metadata in result');
                        }
                        
                        if (result.tables) {
                            console.log('Tables found:', result.tables.length);
                            displayTables(result.tables);
                        }
                        
                        if (result.text) {
                            console.log('Text found, length:', result.text.length);
                            displayText(result.text);
                        }
                        
                        displayDownloads(jobId);
                        
                        // Re-enable form
                        const processBtn = document.getElementById('processBtn');
                        processBtn.disabled = false;
                        processBtn.innerHTML = '<i class="fas fa-search"></i><span>Analyze Document</span>';
                    }, 1000);
                    
                } else if (result.status === 'error') {
                    console.error('Processing error:', result.error);
                    throw new Error(result.error || 'Processing failed');
                } else {
                    // Still processing
                    const progress = Math.min(result.progress || 30, 90);
                    updateProgress(progress, result.message || 'Processing...');
                    
                    // Continue polling
                    setTimeout(() => pollResults(jobId), 2000);
                }
                
            } catch (error) {
                console.error('Error polling results:', error);
                alert('Error: ' + error.message);
                hideProgress();
                
                // Re-enable form
                const processBtn = document.getElementById('processBtn');
                processBtn.disabled = false;
                processBtn.innerHTML = '<i class="fas fa-search"></i><span>Analyze Document</span>';
            }
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'})
        
        file = request.files['file']
        
        if not file or file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if not file.filename.lower().endswith('.pdf'):
            return jsonify({'success': False, 'error': 'Only PDF files are supported'})
        
        # Generate unique job ID
        job_id = str(uuid.uuid4())
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, filename)
        file.save(file_path)
        
        # Store job info
        processing_results[job_id] = {
            'status': 'processing',
            'file_path': file_path,
            'temp_dir': temp_dir,
            'progress': 0,
            'message': 'Starting comprehensive analysis...'
        }
        
        # Start processing in background thread
        thread = threading.Thread(target=process_pdf_background, args=(job_id, file_path, temp_dir))
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'job_id': job_id})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def process_pdf_background(job_id, file_path, temp_dir):
    """Process PDF in background thread with comprehensive forensic analysis and normal table formatting"""
    try:
        # Update progress
        processing_results[job_id]['progress'] = 10
        processing_results[job_id]['message'] = 'Starting comprehensive forensic analysis...'
        
        # Extract comprehensive metadata for forensic analysis
        print(f"Starting comprehensive forensic analysis for job {job_id}")
        metadata = extract_pdf_metadata(file_path)
        print(f"DEBUG: Comprehensive analysis returned: {type(metadata)}")
        
        # Validate metadata
        if metadata is None:
            print("ERROR: Comprehensive analysis returned None")
            metadata = {
                'basic_info': {'Error': 'Forensic analysis failed'},
                'security_info': {'encrypted': False, 'revisions': 0},
                'forensic_indicators': ['Comprehensive analysis failed'],
                'risk_assessment': 'Unknown',
                'recommendations': ['Unable to perform analysis']
            }
        elif not isinstance(metadata, dict):
            print(f"ERROR: Comprehensive analysis returned non-dict: {type(metadata)}")
            metadata = {
                'basic_info': {'Error': f'Analysis returned invalid type: {type(metadata)}'},
                'security_info': {'encrypted': False, 'revisions': 0},
                'forensic_indicators': ['Analysis failed - invalid return type'],
                'risk_assessment': 'Unknown',
                'recommendations': ['Unable to perform analysis']
            }
        
        # Store metadata immediately
        processing_results[job_id]['metadata'] = metadata
        print(f"DEBUG: Stored comprehensive metadata in processing_results")
        
        processing_results[job_id]['progress'] = 30
        processing_results[job_id]['message'] = 'Initializing document processor...'
        
        # Initialize client with hardcoded API key
        client = Mistral(api_key=MISTRAL_API_KEY)
        
        processing_results[job_id]['progress'] = 40
        processing_results[job_id]['message'] = 'Uploading for OCR processing...'
        
        # Upload for OCR
        with open(file_path, "rb") as f:
            content = f.read()
        
        uploaded = client.files.upload(
            file={
                "file_name": os.path.basename(file_path),
                "content": content
            },
            purpose="ocr"
        )
        
        processing_results[job_id]['progress'] = 60
        processing_results[job_id]['message'] = 'Getting signed URL...'
        
        # Get a signed URL
        signed = client.files.get_signed_url(file_id=uploaded.id)
        signed_url = signed.url
        
        processing_results[job_id]['progress'] = 70
        processing_results[job_id]['message'] = 'Running OCR processing...'
        
        # Run the OCR model
        ocr_response = client.ocr.process(
            model="mistral-ocr-latest",
            include_image_base64=True,
            document={
                "type": "document_url",
                "document_url": signed_url
            }
        )
        
        processing_results[job_id]['progress'] = 80
        processing_results[job_id]['message'] = 'Extracting and formatting tables...'
        
        # Process each page
        all_tables = []
        all_markdown = ""
        
        for page in ocr_response.pages:
            blob = json.loads(page.model_dump_json())
            markdown = blob.get("markdown", "")
            all_markdown += markdown + "\n\n"
            
            # Extract tables from the markdown
            tables = extract_tables_from_markdown(markdown)
            all_tables.extend(tables)
        
        processing_results[job_id]['progress'] = 85
        processing_results[job_id]['message'] = 'Processing and formatting tables...'
        
        # Parse and format tables with our improved parsing
        parsed_tables = []
        output_dir = os.path.join(temp_dir, "extracted_tables")
        os.makedirs(output_dir, exist_ok=True)
        
        if all_tables:
            print(f"\nDEBUG: Found {len(all_tables)} tables, starting formatting...")
            
            for i, table_lines in enumerate(all_tables):
                try:
                    # Parse table with our improved parser
                    df = parse_table(table_lines)
                    
                    if not df.empty:
                        # Save table files
                        base_filename = os.path.join(output_dir, f"formatted_table_{i+1}")
                        csv_file, excel_file = save_table(df, base_filename)
                        
                        # Convert DataFrame to JSON-serializable format
                        table_data = {
                            'columns': df.columns.tolist(),
                            'data': df.to_dict('records'),
                            'csv_file': csv_file,
                            'excel_file': excel_file
                        }
                        parsed_tables.append(table_data)
                        print(f"DEBUG: Successfully processed table {i+1}")
                except Exception as e:
                    print(f"Error processing table {i+1}: {e}")
                    continue
        else:
            print("DEBUG: No tables found for formatting")
        
        processing_results[job_id]['progress'] = 95
        processing_results[job_id]['message'] = 'Finalizing comprehensive analysis...'
        
        # Save full text
        text_file = os.path.join(output_dir, "full_text.txt")
        with open(text_file, "w", encoding="utf-8") as f:
            f.write(all_markdown)
        
        # Save comprehensive forensic report
        forensic_report_file = os.path.join(output_dir, "forensic_analysis_report.json")
        with open(forensic_report_file, "w", encoding="utf-8") as f:
            # Convert to JSON-serializable format and handle NaN values
            json_safe_metadata = json.loads(json.dumps(metadata, indent=2, default=str, ensure_ascii=False))
            json.dump(json_safe_metadata, f, indent=2, ensure_ascii=False)
        
        # Handle NaN values in tables data for JSON serialization
        json_safe_tables = []
        for table in parsed_tables:
            if isinstance(table, dict):
                # Convert DataFrame data to be JSON-safe
                if 'data' in table and isinstance(table['data'], list):
                    safe_data = []
                    for row in table['data']:
                        if isinstance(row, dict):
                            safe_row = {}
                            for key, value in row.items():
                                # Handle NaN, None, and inf values
                                if pd.isna(value) or value is None:
                                    safe_row[key] = ""
                                elif isinstance(value, float) and (np.isinf(value) or np.isnan(value)):
                                    safe_row[key] = ""
                                else:
                                    safe_row[key] = str(value) if not isinstance(value, (str, int, float, bool)) else value
                            safe_data.append(safe_row)
                        else:
                            safe_data.append(str(row) if row is not None else "")
                    table['data'] = safe_data
                json_safe_tables.append(table)
        
        # Update final results
        processing_results[job_id].update({
            'status': 'completed',
            'progress': 100,
            'message': 'Comprehensive analysis complete with formatted tables!',
            'metadata': metadata,
            'tables': json_safe_tables,
            'text': all_markdown,
            'output_dir': output_dir,
            'text_file': text_file,
            'metadata_file': forensic_report_file
        })
        
        print(f"Job {job_id} completed successfully with comprehensive forensic analysis and formatted tables")
        
    except Exception as e:
        print(f"Error in job {job_id}: {e}")
        traceback.print_exc()
        processing_results[job_id].update({
            'status': 'error',
            'error': str(e),
            'traceback': traceback.format_exc()
        })

@app.route('/status/<job_id>')
def get_status(job_id):
    if job_id not in processing_results:
        return jsonify({'error': 'Job not found'}), 404
    
    result = processing_results[job_id].copy()
    
    # Remove sensitive data from response
    if 'file_path' in result:
        del result['file_path']
    if 'temp_dir' in result:
        del result['temp_dir']
    
    print(f"Returning status for job {job_id}: {result.get('status', 'unknown')}")
    if 'metadata' in result and result['metadata']:
        print(f"Comprehensive metadata sections: {list(result['metadata'].keys())}")
    
    return jsonify(result)

@app.route('/download/<job_id>/<file_type>')
def download_file(job_id, file_type):
    if job_id not in processing_results:
        return "Job not found", 404
    
    result = processing_results[job_id]
    
    if result['status'] != 'completed':
        return "Job not completed", 400
    
    try:
        if file_type == 'all':
            # Create ZIP file with all results
            zip_path = os.path.join(result['temp_dir'], 'comprehensive_analysis_results.zip')
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                # Add all files from output directory
                for root, dirs, files in os.walk(result['output_dir']):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, result['temp_dir'])
                        zipf.write(file_path, arcname)
            
            return send_file(zip_path, as_attachment=True, download_name='comprehensive_analysis_results.zip')
            
        elif file_type == 'metadata':
            return send_file(result['metadata_file'], as_attachment=True, download_name='forensic_analysis_report.json')
            
        elif file_type == 'text':
            return send_file(result['text_file'], as_attachment=True, download_name='full_text.txt')
            
        else:
            return "Invalid file type", 400
            
    except Exception as e:
        return f"Error downloading file: {str(e)}", 500

if __name__ == '__main__':
    print("🚀 Starting PDF Forensic Analyzer Pro")
    print("📍 Open your browser and go to: http://localhost:5000")
    print("🔍 Now featuring comprehensive forensic analysis capabilities")
    print("🎯 Enhanced table extraction with intelligent formatting")
    print("\n" + "="*60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)