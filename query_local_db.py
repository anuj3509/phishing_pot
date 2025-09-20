#!/usr/bin/env python3
"""
Query Local Database for Phishing Emails

This script queries the local RAG retrieval system for specific substrings
and patterns in phishing emails.
"""

import sys
import argparse
from simple_rag_retrieval import SimpleHybridRetriever


def query_substring(retriever, substring, top_k=10):
    """Query for emails containing a specific substring"""
    print(f"\n🔍 Searching for emails containing: '{substring}'")
    print("=" * 80)
    
    # Use the simple search with the substring as query
    results = retriever.simple_search(substring, top_k=top_k)
    
    if not results:
        print("❌ No emails found containing this substring.")
        return
    
    print(f"📊 Found {len(results)} emails containing '{substring}':")
    print("-" * 80)
    
    for i, result in enumerate(results, 1):
        print(f"\n{i:2d}. Email ID: {result.email_id}")
        print(f"    📧 Subject: {result.subject[:70]}...")
        print(f"    👤 Sender:  {result.sender[:60]}...")
        print(f"    📊 Score:   {result.similarity_score:.3f}")
        print(f"    🎯 Matches: {', '.join(result.match_reasons)}")
        
        if result.urgency_words:
            print(f"    ⚡ Urgency:  {', '.join(result.urgency_words[:5])}")
        
        if result.domains:
            print(f"    🌐 Domains: {', '.join(result.domains[:3])}")
        
        # Show content preview if available
        for analysis in retriever.phishing_analyses:
            if analysis.email_id == result.email_id:
                if analysis.content_preview:
                    preview = analysis.content_preview.lower()
                    if substring.lower() in preview:
                        # Find the context around the substring
                        start = max(0, preview.find(substring.lower()) - 50)
                        end = min(len(preview), preview.find(substring.lower()) + len(substring) + 50)
                        context = analysis.content_preview[start:end]
                        print(f"    📝 Context: ...{context}...")
                break


def query_exact_match(retriever, substring, case_sensitive=False):
    """Find emails with exact substring matches in content"""
    print(f"\n🎯 Searching for EXACT matches of: '{substring}'")
    if not case_sensitive:
        print("    (Case-insensitive search)")
    print("=" * 80)
    
    matches = []
    search_term = substring if case_sensitive else substring.lower()
    
    for analysis in retriever.phishing_analyses:
        # Check in subject
        subject_text = analysis.subject if case_sensitive else analysis.subject.lower()
        subject_match = search_term in subject_text
        
        # Check in content preview
        content_text = analysis.content_preview if case_sensitive else analysis.content_preview.lower()
        content_match = search_term in content_text
        
        # Check in analysis text
        analysis_text = analysis.analysis_text if case_sensitive else analysis.analysis_text.lower()
        analysis_match = search_term in analysis_text
        
        if subject_match or content_match or analysis_match:
            match_locations = []
            if subject_match:
                match_locations.append("Subject")
            if content_match:
                match_locations.append("Content")
            if analysis_match:
                match_locations.append("Analysis")
            
            matches.append({
                'analysis': analysis,
                'locations': match_locations,
                'subject_match': subject_match,
                'content_match': content_match,
                'analysis_match': analysis_match
            })
    
    if not matches:
        print(f"❌ No emails found with exact substring '{substring}'.")
        return
    
    print(f"📊 Found {len(matches)} emails with exact matches:")
    print("-" * 80)
    
    for i, match in enumerate(matches, 1):
        analysis = match['analysis']
        print(f"\n{i:2d}. Email ID: {analysis.email_id}")
        print(f"    📧 Subject: {analysis.subject[:70]}...")
        print(f"    👤 Sender:  {analysis.sender[:60]}...")
        print(f"    📍 Found in: {', '.join(match['locations'])}")
        
        if analysis.urgency_words:
            print(f"    ⚡ Urgency: {', '.join(analysis.urgency_words[:5])}")
        
        if analysis.domains:
            print(f"    🌐 Domains: {', '.join(analysis.domains[:3])}")
        
        # Show context where the substring was found
        if match['subject_match']:
            print(f"    📧 Subject context: {analysis.subject}")
        
        if match['content_match']:
            content = analysis.content_preview
            if not case_sensitive:
                # Find the actual case in original content
                content_lower = content.lower()
                pos = content_lower.find(search_term)
                if pos != -1:
                    start = max(0, pos - 50)
                    end = min(len(content), pos + len(substring) + 50)
                    context = content[start:end]
                    print(f"    📝 Content context: ...{context}...")
        
        if match['analysis_match']:
            # Extract relevant line from analysis
            lines = analysis.analysis_text.split('\n')
            for line in lines:
                line_check = line if case_sensitive else line.lower()
                if search_term in line_check:
                    print(f"    🔍 Analysis context: {line.strip()}")
                    break


def interactive_query(retriever):
    """Interactive query mode"""
    print("\n" + "=" * 70)
    print("  🔍 INTERACTIVE DATABASE QUERY MODE")
    print("=" * 70)
    
    while True:
        print("\n📋 Query Options:")
        print("1. 🔍 Similarity search (fuzzy matching)")
        print("2. 🎯 Exact substring search")
        print("3. 📈 Show database statistics")
        print("0. 🚪 Exit")
        
        choice = input("\nEnter your choice (0-3): ").strip()
        
        if choice == "0":
            print("👋 Goodbye!")
            break
        
        elif choice == "1":
            query = input("Enter search query: ").strip()
            if query:
                try:
                    top_k = int(input("Number of results (default 10): ") or "10")
                except ValueError:
                    top_k = 10
                
                query_substring(retriever, query, top_k)
        
        elif choice == "2":
            substring = input("Enter exact substring to search: ").strip()
            if substring:
                case_sensitive = input("Case sensitive? (y/n, default n): ").strip().lower() == 'y'
                query_exact_match(retriever, substring, case_sensitive)
        
        elif choice == "3":
            stats = retriever._get_index_stats()
            patterns = retriever.analyze_patterns()
            
            print(f"\n📊 Database Statistics:")
            print(f"   Total emails: {stats['total_emails']}")
            print(f"   Unique domains: {stats['unique_domains']}")
            print(f"   Unique urgency words: {stats['unique_urgency_words']}")
            print(f"   Unique words: {stats['unique_words']}")
            print(f"   Emails with URLs: {patterns['emails_with_urls']}")
            print(f"   Emails with urgency words: {patterns['emails_with_urgency']}")
            
            print(f"\n🔝 Top 5 patterns:")
            print("   Domains:", [f"{d}({c})" for d, c in patterns['top_domains'][:5]])
            print("   Urgency:", [f"{w}({c})" for w, c in patterns['top_urgency_words'][:5]])
        
        else:
            print("❌ Invalid choice. Please try again.")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Query local phishing email database")
    parser.add_argument("--query", help="Search query (similarity search)")
    parser.add_argument("--exact", help="Exact substring to search for")
    parser.add_argument("--case-sensitive", action="store_true", help="Case sensitive exact search")
    parser.add_argument("--top-k", type=int, default=10, help="Number of results to return")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--data-dir", default="data/decoded_emails", help="Data directory")
    
    args = parser.parse_args()
    
    # Initialize retriever
    print("🚀 Initializing Local Database Query System...")
    retriever = SimpleHybridRetriever(args.data_dir)
    
    # Build index
    print("📊 Building search index...")
    stats = retriever.build_index()
    
    print(f"\n✅ Database ready!")
    print(f"   Total emails indexed: {stats['total_emails']}")
    print(f"   Unique domains: {stats['unique_domains']}")
    print(f"   Unique urgency words: {stats['unique_urgency_words']}")
    
    # Handle different modes
    if args.interactive:
        interactive_query(retriever)
    
    elif args.query:
        query_substring(retriever, args.query, args.top_k)
    
    elif args.exact:
        query_exact_match(retriever, args.exact, args.case_sensitive)
    
    else:
        # Default: search for "urgent account verification"
        print("\n🔍 Default search: 'urgent account verification'")
        query_substring(retriever, "urgent account verification", args.top_k)
        
        print("\n" + "-" * 80)
        print("💡 Usage examples:")
        print("   python3 query_local_db.py --query 'paypal suspended'")
        print("   python3 query_local_db.py --exact 'urgent account verification'")
        print("   python3 query_local_db.py --exact 'URGENT' --case-sensitive")
        print("   python3 query_local_db.py --interactive")


if __name__ == "__main__":
    main()
