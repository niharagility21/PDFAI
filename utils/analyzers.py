import re
import os
import logging
import hashlib
import datetime
import xml.etree.ElementTree as ET
from collections import defaultdict, Counter
import PyPDF2

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

forensic_logger = logging.getLogger('forensic_analysis')
error_logger = logging.getLogger('errors')

# Analysis rules
XMP_ANALYSIS_RULES = {
    'software_patterns': {
        'Adobe Photoshop': r'photoshop|ps:|adobe:photoshop',
        'Adobe Acrobat': r'acrobat|pdf:|adobe:acrobat',
        'Adobe InDesign': r'indesign|adobe:indesign',
        'Microsoft Word': r'microsoft\s+word|word|winword',
        'LibreOffice': r'libreoffice|openoffice',
        'Google Docs': r'google\s+docs|docs\.google',
        'Canva': r'canva',
        'PDF Editors': r'foxit|nitro|pdfcreator|pdfelement|smallpdf'
    },
    'date_fields': ['ModifyDate', 'MetadataDate', 'CreateDate', 'modifyDate', 'createDate']
}

OBJECT_ANALYSIS_RULES = {
    'suspicious_patterns': [
        (r'/JavaScript', 'JavaScript code found'),
        (r'/JS', 'JavaScript code found'),
        (r'/EmbeddedFile', 'Embedded file detected'),
        (r'/FileAttachment', 'File attachment found'),
        (r'/GoToR', 'External reference found'),
        (r'/Launch', 'Launch action found'),
        (r'/Form', 'Form fields present'),
        (r'/Annot', 'Annotation found')
    ]
}

FONT_ANALYSIS_RULES = {
    'editing_fonts': ['Arial', 'Helvetica', 'Times', 'Courier', 'Calibri']
}

def generic_analyzer(inputs, rules, extract_fn):
    """Generic analyzer that applies rules using the provided extraction function."""
    results = {
        'findings': [],
        'suspicious_patterns': [],
        'metadata': {}
    }
    
    try:
        extracted_data = extract_fn(inputs)
        results['metadata'] = extracted_data
        
        # Apply rules based on the extracted data
        for rule_name, rule_config in rules.items():
            if rule_name in extracted_data:
                results['findings'].extend(extracted_data[rule_name])
        
    except Exception as e:
        error_msg = f"Analysis error: {str(e)}"
        results['suspicious_patterns'].append(error_msg)
        error_logger.error(f"Generic analysis failed: {e}", exc_info=True)
    
    return results

def analyze_xmp_metadata(xmp_info):
    """Detailed XMP metadata analysis for forensic purposes."""
    forensic_logger.info("Starting XMP metadata analysis")
    
    xmp_analysis = {
        'software_used': [],
        'modification_history': [],
        'creation_tools': [],
        'editing_sessions': [],
        'suspicious_patterns': []
    }
    
    if not xmp_info:
        forensic_logger.warning("No XMP metadata found")
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
            for software, pattern in XMP_ANALYSIS_RULES['software_patterns'].items():
                if re.search(pattern, xmp_str, re.IGNORECASE):
                    xmp_analysis['software_used'].append(software)
                    forensic_logger.info(f"Found software in XMP: {software}")
            
            # Look for modification dates and sequences
            modification_dates = []
            
            for elem in root.iter():
                if elem.tag and any(date_field.lower() in elem.tag.lower() 
                                  for date_field in XMP_ANALYSIS_RULES['date_fields']):
                    if elem.text:
                        modification_dates.append({
                            'field': elem.tag,
                            'value': elem.text,
                            'timestamp': elem.text
                        })
            
            # Analyze modification patterns
            if len(modification_dates) > 2:
                suspicious_pattern = f"Multiple modification timestamps found ({len(modification_dates)})"
                xmp_analysis['suspicious_patterns'].append(suspicious_pattern)
                forensic_logger.warning(f"Suspicious XMP pattern: {suspicious_pattern}")
            
        except ET.ParseError:
            # Fallback to regex parsing if XML parsing fails
            software_mentions = re.findall(r'(?:creator|producer|application)["\']?\s*[:=]\s*["\']?([^"\'>\n]+)', 
                                         xmp_str, re.IGNORECASE)
            xmp_analysis['software_used'].extend(software_mentions)
            forensic_logger.debug("Used regex fallback for XMP parsing")
            
    except Exception as e:
        error_msg = f"XMP parsing error: {str(e)}"
        xmp_analysis['suspicious_patterns'].append(error_msg)
        error_logger.error(f"XMP analysis failed: {e}", exc_info=True)
    
    forensic_logger.info(f"XMP analysis complete. Found {len(xmp_analysis['software_used'])} software entries")
    return xmp_analysis

def analyze_pdf_objects(pdf_path):
    """Analyze PDF object structure for signs of modification."""
    forensic_logger.info(f"Starting PDF object analysis for: {pdf_path}")
    
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
        forensic_logger.info(f"Found {len(objects)} PDF objects")
        
        # Look for suspicious object patterns
        content_str = content.decode('latin-1', errors='ignore')
        for pattern, description in OBJECT_ANALYSIS_RULES['suspicious_patterns']:
            matches = re.findall(pattern, content_str, re.IGNORECASE)
            if matches:
                finding = f"{description} ({len(matches)} instances)"
                object_analysis['suspicious_objects'].append(finding)
                forensic_logger.warning(f"Suspicious object found: {finding}")
        
        # Analyze cross-reference table
        xref_pattern = r'xref\s*\n.*?trailer'
        xref_matches = re.findall(xref_pattern, content_str, re.DOTALL)
        if len(xref_matches) > 1:
            finding = f"Multiple cross-reference tables found ({len(xref_matches)})"
            object_analysis['potential_modifications'].append(finding)
            forensic_logger.warning(f"Potential modification: {finding}")
        
        # Look for incremental updates
        eof_count = content.count(b'%%EOF')
        if eof_count > 1:
            finding = f"Document has {eof_count-1} incremental updates"
            object_analysis['potential_modifications'].append(finding)
            forensic_logger.warning(f"Incremental updates found: {finding}")
        
        # Check for object streams (can hide modifications)
        obj_stream_count = len(re.findall(r'/ObjStm', content_str, re.IGNORECASE))
        if obj_stream_count > 0:
            finding = f"Object streams found ({obj_stream_count}) - can hide object modifications"
            object_analysis['suspicious_objects'].append(finding)
            forensic_logger.warning(f"Object streams detected: {finding}")
        
    except Exception as e:
        error_msg = f"Object analysis error: {str(e)}"
        object_analysis['potential_modifications'].append(error_msg)
        error_logger.error(f"PDF object analysis failed: {e}", exc_info=True)
    
    forensic_logger.info("PDF object analysis complete")
    return object_analysis

def analyze_fonts(pdf):
    """Analyze fonts used in the PDF for inconsistencies."""
    forensic_logger.info("Starting font analysis")
    
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
        forensic_logger.info(f"Found {len(fonts_found)} unique fonts")
        
        # Analyze font patterns
        if len(fonts_found) > 10:
            pattern = f"Unusually high number of fonts ({len(fonts_found)})"
            font_analysis['suspicious_patterns'].append(pattern)
            forensic_logger.warning(f"Font anomaly: {pattern}")
        
        # Check for mix of embedded and system fonts
        if font_analysis['embedded_fonts'] > 0 and font_analysis['system_fonts'] > 0:
            inconsistency = "Mix of embedded and system fonts - possible text replacement"
            font_analysis['font_inconsistencies'].append(inconsistency)
            forensic_logger.warning(f"Font inconsistency: {inconsistency}")
        
        # Look for common editing software fonts
        common_fonts_used = [f for f in fonts_found 
                           if any(ef in str(f) for ef in FONT_ANALYSIS_RULES['editing_fonts'])]
        if len(common_fonts_used) > 0 and len(fonts_found) > len(common_fonts_used):
            pattern = "Mix of standard and non-standard fonts detected"
            font_analysis['suspicious_patterns'].append(pattern)
            forensic_logger.info(f"Font pattern: {pattern}")
        
    except Exception as e:
        error_msg = f"Font analysis error: {str(e)}"
        font_analysis['suspicious_patterns'].append(error_msg)
        error_logger.error(f"Font analysis failed: {e}", exc_info=True)
    
    forensic_logger.info("Font analysis complete")
    return font_analysis

def analyze_images(pdf, pdf_path):
    """Analyze images in the PDF for modifications."""
    forensic_logger.info("Starting image analysis")
    
    image_analysis = {
        'total_images': 0,
        'image_details': [],
        'suspicious_patterns': [],
        'compression_inconsistencies': [],
        'metadata_findings': []
    }
    
    if not PILLOW_AVAILABLE:
        warning = "Image analysis limited - Pillow not available"
        image_analysis['suspicious_patterns'].append(warning)
        forensic_logger.warning(warning)
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
                                                import io
                                                img = Image.open(io.BytesIO(image_data))
                                                
                                                # Check EXIF data
                                                if hasattr(img, '_getexif') and img._getexif():
                                                    exif_data = img._getexif()
                                                    if exif_data:
                                                        for tag_id, value in exif_data.items():
                                                            tag = TAGS.get(tag_id, tag_id)
                                                            if tag in ['Software', 'DateTime', 'DateTimeOriginal', 'DateTimeDigitized']:
                                                                finding = f"Image {obj_name}: {tag} = {value}"
                                                                image_analysis['metadata_findings'].append(finding)
                                                                forensic_logger.info(f"Image metadata: {finding}")
                                                
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
                inconsistency = f"Multiple image formats found: {dict(format_counts)}"
                image_analysis['compression_inconsistencies'].append(inconsistency)
                forensic_logger.warning(f"Image format inconsistency: {inconsistency}")
            
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
                pattern = "Significant resolution differences between images"
                image_analysis['suspicious_patterns'].append(pattern)
                forensic_logger.warning(f"Image resolution anomaly: {pattern}")
        
        forensic_logger.info(f"Image analysis complete. Found {image_analysis['total_images']} images")
        
    except Exception as e:
        error_msg = f"Image analysis error: {str(e)}"
        image_analysis['suspicious_patterns'].append(error_msg)
        error_logger.error(f"Image analysis failed: {e}", exc_info=True)
    
    return image_analysis

def calculate_file_hash(filepath):
    """Calculate file hash for integrity verification."""
    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()
    
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha256.update(chunk)
        
        hashes = {
            'md5': hash_md5.hexdigest(),
            'sha256': hash_sha256.hexdigest()
        }
        return hashes
    except Exception as e:
        error_logger.error(f"Hash calculation failed: {e}", exc_info=True)
        return {'error': str(e)}

def extract_pdf_metadata(pdf_path):
    """Extract comprehensive metadata from PDF for detailed forensic analysis."""
    forensic_logger.info(f"Starting comprehensive PDF forensic analysis for: {pdf_path}")
    
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
        forensic_logger.info("Calculating file integrity hashes")
        metadata_results['detailed_analysis']['file_integrity'] = calculate_file_hash(pdf_path)
        
        with open(pdf_path, 'rb') as file:
            pdf = PyPDF2.PdfReader(file)
            
            # Basic document information
            forensic_logger.info("Extracting basic document information")
            info = pdf.metadata
            if info:
                forensic_logger.info("Document Information Dictionary found")
                
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
                                        metadata_results['_creation_date'] = formatted_date
                                    elif key == '/ModDate':
                                        metadata_results['modification_timeline'].append({
                                            'event': 'Document Modified',
                                            'timestamp': formatted_date,
                                            'source': 'PDF Metadata'
                                        })
                                        metadata_results['_modification_date'] = formatted_date
                        except Exception as date_error:
                            forensic_logger.warning(f"Date parsing error for {key}: {date_error}")
                    
                    forensic_logger.debug(f"{label}: {value}")
                    metadata_results['basic_info'][label] = str(value) if value is not None else "Not available"
                    
                    # Track editing software
                    if key in ['/Creator', '/Producer'] and value != "Not available":
                        software = str(value).lower()
                        if any(editor in software for editor in ['photoshop', 'acrobat', 'word', 'libreoffice', 'canva', 'foxit']):
                            metadata_results['editing_software_detected'].append(f"{label}: {value}")
                            forensic_logger.info(f"Editing software detected: {label}: {value}")
            
            # Enhanced XMP metadata analysis
            forensic_logger.info("Performing detailed XMP metadata analysis")
            try:
                xmp_info = pdf.xmp_metadata
                metadata_results['detailed_analysis']['xmp_analysis'] = analyze_xmp_metadata(xmp_info)
                
                if metadata_results['detailed_analysis']['xmp_analysis']['software_used']:
                    for software in metadata_results['detailed_analysis']['xmp_analysis']['software_used']:
                        metadata_results['editing_software_detected'].append(f"XMP: {software}")
                
            except Exception as xmp_error:
                forensic_logger.error(f"XMP analysis error: {xmp_error}")
                metadata_results['detailed_analysis']['xmp_analysis'] = {'error': str(xmp_error)}
            
            # PDF object structure analysis
            forensic_logger.info("Analyzing PDF object structure")
            metadata_results['detailed_analysis']['object_analysis'] = analyze_pdf_objects(pdf_path)
            
            if metadata_results['detailed_analysis']['object_analysis']['suspicious_objects']:
                for obj in metadata_results['detailed_analysis']['object_analysis']['suspicious_objects']:
                    metadata_results['suspicious_behaviors'].append(obj)
            
            # Font analysis
            forensic_logger.info("Analyzing fonts and typography")
            metadata_results['detailed_analysis']['font_analysis'] = analyze_fonts(pdf)
            
            if metadata_results['detailed_analysis']['font_analysis']['font_inconsistencies']:
                for inconsistency in metadata_results['detailed_analysis']['font_analysis']['font_inconsistencies']:
                    metadata_results['suspicious_behaviors'].append(f"Font: {inconsistency}")
            
            # Image analysis
            forensic_logger.info("Analyzing embedded images")
            metadata_results['detailed_analysis']['image_analysis'] = analyze_images(pdf, pdf_path)
            
            if metadata_results['detailed_analysis']['image_analysis']['total_images'] > 0:
                if metadata_results['detailed_analysis']['image_analysis']['metadata_findings']:
                    for finding in metadata_results['detailed_analysis']['image_analysis']['metadata_findings']:
                        metadata_results['modification_timeline'].append({
                            'event': 'Image Metadata',
                            'details': finding,
                            'source': 'Image EXIF'
                        })
            
            # Security analysis
            forensic_logger.info("Performing security analysis")
            metadata_results['security_info']['encrypted'] = pdf.is_encrypted
            if pdf.is_encrypted:
                forensic_logger.warning("ALERT: Document is encrypted")
                metadata_results['forensic_indicators'].append("Document is encrypted - can hide editing history")
            
            # Check for incremental updates and revisions
            try:
                with open(pdf_path, 'rb') as f:
                    content = f.read()
                    eof_count = content.count(b"%%EOF")
                    metadata_results['security_info']['revisions'] = eof_count - 1
                    
                    if eof_count > 1:
                        forensic_logger.warning(f"WARNING: Found {eof_count} EOF markers")
                        metadata_results['forensic_indicators'].append(f"Document revised {eof_count-1} times")
                        metadata_results['modification_timeline'].append({
                            'event': f'Document Revisions Detected ({eof_count-1})',
                            'details': 'Incremental updates found',
                            'source': 'PDF Structure'
                        })
            except Exception as rev_error:
                forensic_logger.error(f"Revision analysis error: {rev_error}")
            
            # Page analysis
            page_count = len(pdf.pages)
            metadata_results['basic_info']['Page Count'] = str(page_count)
            
            # Check for post-creation editing by comparing dates
            if '_creation_date' in metadata_results and '_modification_date' in metadata_results:
                try:
                    creation_date = metadata_results['_creation_date']
                    modification_date = metadata_results['_modification_date']
                    
                    if creation_date != modification_date:
                        forensic_logger.warning(f"ALERT: Document was edited after creation!")
                        metadata_results['forensic_indicators'].append(f"Document edited after creation")
                        metadata_results['suspicious_behaviors'].append(f"Post-creation editing detected")
                        metadata_results['modification_timeline'].append({
                            'event': 'Post-Creation Editing Detected',
                            'details': f"Document was modified after initial creation",
                            'source': 'Timeline Analysis'
                        })
                except Exception as date_compare_error:
                    forensic_logger.error(f"Error comparing dates: {date_compare_error}")
            
            # Clean up temporary date fields
            if '_creation_date' in metadata_results:
                del metadata_results['_creation_date']
            if '_modification_date' in metadata_results:
                del metadata_results['_modification_date']
            
            # Risk assessment
            forensic_logger.info("Performing comprehensive risk assessment")
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
            
            # Check for post-creation editing
            post_creation_editing = any('Post-creation editing detected' in str(behavior) 
                                      for behavior in metadata_results.get('suspicious_behaviors', []))
            if post_creation_editing:
                risk_score += 3
                risk_factors.append("Document edited after creation")
            
            # Determine risk level
            if risk_score >= 8:
                metadata_results['risk_assessment'] = 'High'
                metadata_results['recommendations'].extend([
                    "Document shows multiple signs of modification",
                    "Perform thorough verification with original source",
                    "Consider professional forensic analysis"
                ])
            elif risk_score >= 4:
                metadata_results['risk_assessment'] = 'Medium'
                metadata_results['recommendations'].extend([
                    "Some suspicious indicators detected",
                    "Cross-verify information with alternative sources"
                ])
            else:
                metadata_results['risk_assessment'] = 'Low'
                metadata_results['recommendations'].append("No major risk indicators detected")
            
            metadata_results['risk_score'] = f"{risk_score}/10"
            
    except Exception as e:
        metadata_results['error'] = str(e)
        error_logger.error(f"Error in comprehensive forensic analysis: {str(e)}", exc_info=True)
    
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
    
    forensic_logger.info("Comprehensive forensic analysis complete")
    return metadata_results
