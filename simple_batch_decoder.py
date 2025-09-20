#!/usr/bin/env python3
"""
Simple Batch Email Decoder

A lightweight version that processes all .eml files in the email folder
and saves decoded versions to a data folder without external dependencies.
"""

import os
import json
import csv
from pathlib import Path
from email_decoder import EmailDecoder


def create_data_structure(output_dir):
    """Create the data folder structure"""
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    subdirs = ['decoded_emails', 'metadata', 'analysis']
    for subdir in subdirs:
        (output_path / subdir).mkdir(exist_ok=True)
    
    return output_path


def process_all_emails(input_dir='email', output_dir='data'):
    """Process all emails in the input directory"""
    
    print(f"🚀 Starting batch email processing...")
    print(f"Input directory: {input_dir}")
    print(f"Output directory: {output_dir}")
    
    # Create output structure
    output_path = create_data_structure(output_dir)
    
    # Find all email files
    input_path = Path(input_dir)
    if not input_path.exists():
        print(f"❌ Error: Input directory '{input_dir}' not found")
        return False
    
    eml_files = list(input_path.glob("*.eml"))
    if not eml_files:
        print(f"❌ Error: No .eml files found in '{input_dir}'")
        return False
    
    print(f"📧 Found {len(eml_files)} email files to process")
    
    # Initialize decoder and statistics
    decoder = EmailDecoder()
    stats = {
        'total_files': len(eml_files),
        'processed': 0,
        'failed': 0,
        'phishing_indicators': 0,
        'with_attachments': 0,
        'with_urls': 0
    }
    
    results = []
    failed_files = []
    
    # Process each email
    for i, email_file in enumerate(eml_files, 1):
        print(f"Processing {i}/{len(eml_files)}: {email_file.name}", end='... ')
        
        try:
            # Decode the email
            result = decoder.decode_email_file(str(email_file))
            
            if 'error' in result:
                print(f"❌ FAILED: {result['error']}")
                stats['failed'] += 1
                failed_files.append({'file': str(email_file), 'error': result['error']})
                continue
            
            # Generate output filenames
            base_name = email_file.stem
            
            # Save decoded text version
            text_file = output_path / "decoded_emails" / f"{base_name}.txt"
            decoder.save_decoded_email(result, str(text_file))
            
            # Save JSON metadata
            json_file = output_path / "metadata" / f"{base_name}.json"
            metadata = {
                'headers': result['headers'],
                'encoding_info': result['encoding_info'],
                'attachments': result['attachments'],
                'phishing_analysis': result['phishing_analysis'],
                'content_stats': {
                    'text_length': len(result.get('body_text', '')),
                    'html_length': len(result.get('body_html', '')),
                    'has_text': bool(result.get('body_text', '').strip()),
                    'has_html': bool(result.get('body_html', '').strip())
                }
            }
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            # Update statistics
            analysis = result.get('phishing_analysis', {})
            has_phishing_indicators = bool(
                analysis.get('urgency_words') or 
                analysis.get('suspicious_phrases') or 
                analysis.get('suspicious_domains')
            )
            
            result_summary = {
                'file': str(email_file),
                'base_name': base_name,
                'subject': result['headers'].get('subject', ''),
                'sender': result['headers'].get('from', ''),
                'date': result['headers'].get('date', ''),
                'has_phishing_indicators': has_phishing_indicators,
                'has_attachments': bool(result.get('attachments')),
                'has_urls': bool(analysis.get('urls')),
                'url_count': len(analysis.get('urls', [])),
                'attachment_count': len(result.get('attachments', [])),
                'text_length': len(result.get('body_text', '')),
                'html_length': len(result.get('body_html', ''))
            }
            
            results.append(result_summary)
            stats['processed'] += 1
            
            if has_phishing_indicators:
                stats['phishing_indicators'] += 1
            if result.get('attachments'):
                stats['with_attachments'] += 1
            if analysis.get('urls'):
                stats['with_urls'] += 1
            
            print("✅ SUCCESS")
            
        except Exception as e:
            print(f"❌ FAILED: {str(e)}")
            stats['failed'] += 1
            failed_files.append({'file': str(email_file), 'error': str(e)})
    
    # Save summary files
    print(f"\n📊 Saving summary files...")
    
    # Email summary CSV
    if results:
        summary_file = output_path / "email_summary.csv"
        with open(summary_file, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'base_name', 'subject', 'sender', 'date', 
                'has_phishing_indicators', 'has_attachments', 'has_urls',
                'url_count', 'attachment_count', 'text_length', 'html_length'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in results:
                writer.writerow({k: result.get(k, '') for k in fieldnames})
    
    # Processing statistics
    stats_file = output_path / "processing_statistics.csv"
    with open(stats_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Metric', 'Value'])
        for key, value in stats.items():
            writer.writerow([key.replace('_', ' ').title(), value])
    
    # Failed files (if any)
    if failed_files:
        failed_file = output_path / "failed_emails.csv"
        with open(failed_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['File', 'Error'])
            for failed in failed_files:
                writer.writerow([failed['file'], failed['error']])
    
    # Analysis report
    report_file = output_path / "analysis" / "processing_report.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("EMAIL PROCESSING REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("PROCESSING STATISTICS:\n")
        f.write("-" * 30 + "\n")
        for key, value in stats.items():
            f.write(f"{key.replace('_', ' ').title()}: {value}\n")
        
        success_rate = (stats['processed'] / stats['total_files'] * 100) if stats['total_files'] > 0 else 0
        f.write(f"\nSuccess Rate: {success_rate:.1f}%\n")
        
        if stats['processed'] > 0:
            phishing_rate = (stats['phishing_indicators'] / stats['processed'] * 100)
            attachment_rate = (stats['with_attachments'] / stats['processed'] * 100)
            url_rate = (stats['with_urls'] / stats['processed'] * 100)
            
            f.write(f"Phishing Indicator Rate: {phishing_rate:.1f}%\n")
            f.write(f"Attachment Rate: {attachment_rate:.1f}%\n")
            f.write(f"URL Rate: {url_rate:.1f}%\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("OUTPUT FILES:\n")
        f.write("-" * 20 + "\n")
        f.write("• decoded_emails/ - Human-readable email content\n")
        f.write("• metadata/ - JSON metadata for each email\n")
        f.write("• email_summary.csv - Summary of all processed emails\n")
        f.write("• processing_statistics.csv - Processing statistics\n")
        if failed_files:
            f.write("• failed_emails.csv - List of failed processing attempts\n")
    
    # Print final summary
    print("\n" + "=" * 60)
    print("🎉 PROCESSING COMPLETE!")
    print("=" * 60)
    print(f"📊 Results:")
    print(f"   Total files: {stats['total_files']}")
    print(f"   Successfully processed: {stats['processed']}")
    print(f"   Failed: {stats['failed']}")
    print(f"   Success rate: {success_rate:.1f}%")
    print()
    print(f"📈 Analysis:")
    print(f"   Emails with phishing indicators: {stats['phishing_indicators']}")
    print(f"   Emails with attachments: {stats['with_attachments']}")
    print(f"   Emails with URLs: {stats['with_urls']}")
    print()
    print(f"📁 Output saved to: {output_path}")
    print()
    print("📋 Files created:")
    print("   • decoded_emails/ - Human-readable versions")
    print("   • metadata/ - JSON metadata")
    print("   • email_summary.csv - Overview spreadsheet")
    print("   • processing_statistics.csv - Statistics")
    print("   • analysis/processing_report.txt - Full report")
    
    if failed_files:
        print("   • failed_emails.csv - Failed processing list")
        print(f"\n⚠️  {len(failed_files)} files failed to process. Check failed_emails.csv for details.")
    
    return True


if __name__ == "__main__":
    import sys
    
    # Allow command line arguments
    input_dir = sys.argv[1] if len(sys.argv) > 1 else 'email'
    output_dir = sys.argv[2] if len(sys.argv) > 2 else 'data'
    
    success = process_all_emails(input_dir, output_dir)
    sys.exit(0 if success else 1)
