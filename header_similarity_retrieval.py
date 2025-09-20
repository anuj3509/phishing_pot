#!/usr/bin/env python3
"""
Header-Based Similarity Retrieval for Phishing Emails

This script retrieves similar emails based on email headers (Subject, From, To, Date)
extracted from the PHISHING ANALYSIS sections and displays results in CLI.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from collections import defaultdict, Counter
import argparse


@dataclass
class EmailHeaders:
    """Structure for email header information"""
    email_id: str
    subject: str
    sender: str
    sender_email: str
    sender_domain: str
    recipient: str
    date: str
    message_id: str
    content_type: str
    subject_words: List[str]
    subject_keywords: List[str]


@dataclass
class HeaderSimilarityResult:
    """Structure for header similarity results"""
    email_id: str
    similarity_score: float
    subject: str
    sender: str
    sender_domain: str
    date: str
    match_types: List[str]
    common_subject_words: List[str]
    header_similarities: Dict[str, str]


class HeaderExtractor:
    """Extracts and parses email headers from decoded files"""
    
    def __init__(self):
        # Common phishing keywords for subject analysis
        self.phishing_keywords = [
            'urgent', 'verify', 'confirm', 'suspend', 'expire', 'update',
            'security', 'alert', 'warning', 'account', 'payment', 'invoice',
            'refund', 'prize', 'winner', 'congratulations', 'claim', 'offer',
            'limited', 'final', 'notice', 'action', 'required', 'immediate'
        ]
        
        # Common sender domains to group by
        self.common_domains = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
            'paypal.com', 'amazon.com', 'microsoft.com', 'apple.com', 'google.com'
        ]
    
    def extract_headers_from_file(self, file_path: str) -> Optional[EmailHeaders]:
        """Extract email headers from a decoded email file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find HEADERS section
            headers_start = content.find('HEADERS:')
            if headers_start == -1:
                return None
            
            headers_end = content.find('ENCODING INFORMATION:', headers_start)
            if headers_end == -1:
                headers_end = content.find('PHISHING ANALYSIS:', headers_start)
            if headers_end == -1:
                headers_end = len(content)
            
            headers_section = content[headers_start:headers_end].strip()
            
            # Parse individual headers
            subject = self._extract_header_value(headers_section, 'Subject:')
            sender = self._extract_header_value(headers_section, 'From:')
            recipient = self._extract_header_value(headers_section, 'To:')
            date = self._extract_header_value(headers_section, 'Date:')
            message_id = self._extract_header_value(headers_section, 'Message_Id:')
            content_type = self._extract_header_value(headers_section, 'Content_Type:')
            
            # Extract sender email and domain
            sender_email = self._extract_email_from_sender(sender)
            sender_domain = self._extract_domain_from_email(sender_email)
            
            # Process subject
            subject_words = self._extract_subject_words(subject)
            subject_keywords = self._extract_subject_keywords(subject)
            
            email_id = Path(file_path).stem
            
            return EmailHeaders(
                email_id=email_id,
                subject=subject,
                sender=sender,
                sender_email=sender_email,
                sender_domain=sender_domain,
                recipient=recipient,
                date=date,
                message_id=message_id,
                content_type=content_type,
                subject_words=subject_words,
                subject_keywords=subject_keywords
            )
            
        except Exception as e:
            print(f"Error extracting headers from {file_path}: {str(e)}")
            return None
    
    def _extract_header_value(self, headers: str, header_name: str) -> str:
        """Extract a specific header value"""
        try:
            pattern = f'{header_name}\\s*(.+?)(?:\\n|$)'
            match = re.search(pattern, headers, re.IGNORECASE | re.MULTILINE)
            return match.group(1).strip() if match else ""
        except:
            return ""
    
    def _extract_email_from_sender(self, sender: str) -> str:
        """Extract email address from sender field"""
        try:
            # Look for email in angle brackets first
            email_match = re.search(r'<([^>]+@[^>]+)>', sender)
            if email_match:
                return email_match.group(1).lower()
            
            # Look for standalone email
            email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', sender)
            if email_match:
                return email_match.group(1).lower()
            
            return ""
        except:
            return ""
    
    def _extract_domain_from_email(self, email: str) -> str:
        """Extract domain from email address"""
        try:
            if '@' in email:
                return email.split('@')[-1].lower()
            return ""
        except:
            return ""
    
    def _extract_subject_words(self, subject: str) -> List[str]:
        """Extract meaningful words from subject"""
        try:
            # Remove common prefixes
            cleaned_subject = re.sub(r'^(re:|fwd?:|fw:)\s*', '', subject, flags=re.IGNORECASE)
            
            # Extract words (alphanumeric, 3+ characters)
            words = re.findall(r'\b[a-zA-Z]{3,}\b', cleaned_subject.lower())
            
            # Filter out very common words
            stop_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'its', 'may', 'new', 'now', 'old', 'see', 'two', 'who', 'boy', 'did', 'she', 'use', 'way', 'what', 'when', 'why', 'will', 'your'}
            
            return [w for w in words if w not in stop_words][:10]  # Limit to 10 words
        except:
            return []
    
    def _extract_subject_keywords(self, subject: str) -> List[str]:
        """Extract phishing-related keywords from subject"""
        try:
            subject_lower = subject.lower()
            found_keywords = []
            
            for keyword in self.phishing_keywords:
                if keyword in subject_lower:
                    found_keywords.append(keyword)
            
            return found_keywords
        except:
            return []


class HeaderSimilarityRetriever:
    """Retrieves similar emails based on header similarities"""
    
    def __init__(self, data_dir: str = "data/decoded_emails"):
        """Initialize the header similarity retriever"""
        self.data_dir = Path(data_dir)
        self.extractor = HeaderExtractor()
        
        # Storage
        self.email_headers: List[EmailHeaders] = []
        self.subject_index: Dict[str, List[int]] = defaultdict(list)
        self.domain_index: Dict[str, List[int]] = defaultdict(list)
        self.keyword_index: Dict[str, List[int]] = defaultdict(list)
        self.sender_index: Dict[str, List[int]] = defaultdict(list)
        
        print(f"Initialized HeaderSimilarityRetriever for directory: {data_dir}")
    
    def build_index(self) -> Dict[str, Any]:
        """Build the header similarity index"""
        print("Building header similarity index...")
        
        # Find all decoded email files
        email_files = list(self.data_dir.glob("*.txt"))
        print(f"Found {len(email_files)} decoded email files")
        
        # Extract headers
        headers_list = []
        failed_count = 0
        
        for email_file in email_files:
            headers = self.extractor.extract_headers_from_file(str(email_file))
            if headers:
                headers_list.append(headers)
            else:
                failed_count += 1
        
        self.email_headers = headers_list
        print(f"Extracted {len(headers_list)} email headers, {failed_count} failed")
        
        if not headers_list:
            raise ValueError("No email headers extracted. Check your data directory.")
        
        # Build indexes
        self._build_indexes()
        
        print("Header index built successfully")
        return self._get_index_stats()
    
    def _build_indexes(self):
        """Build auxiliary indexes for fast retrieval"""
        self.subject_index = defaultdict(list)
        self.domain_index = defaultdict(list)
        self.keyword_index = defaultdict(list)
        self.sender_index = defaultdict(list)
        
        for i, headers in enumerate(self.email_headers):
            # Index by subject words
            for word in headers.subject_words:
                self.subject_index[word.lower()].append(i)
            
            # Index by sender domain
            if headers.sender_domain:
                self.domain_index[headers.sender_domain].append(i)
            
            # Index by keywords
            for keyword in headers.subject_keywords:
                self.keyword_index[keyword.lower()].append(i)
            
            # Index by sender email
            if headers.sender_email:
                self.sender_index[headers.sender_email].append(i)
    
    def find_similar_by_headers(self, email_id: str, top_k: int = 10) -> List[HeaderSimilarityResult]:
        """Find emails with similar headers to a specific email"""
        # Find the target email
        target_headers = None
        for headers in self.email_headers:
            if headers.email_id == email_id:
                target_headers = headers
                break
        
        if not target_headers:
            raise ValueError(f"Email {email_id} not found in index")
        
        # Calculate similarities
        similarities = []
        
        for i, headers in enumerate(self.email_headers):
            if headers.email_id == email_id:
                continue  # Skip self
            
            similarity_score, match_types, common_words, header_sims = self._calculate_header_similarity(
                target_headers, headers
            )
            
            if similarity_score > 0.1:  # Only include emails with some similarity
                result = HeaderSimilarityResult(
                    email_id=headers.email_id,
                    similarity_score=similarity_score,
                    subject=headers.subject,
                    sender=headers.sender,
                    sender_domain=headers.sender_domain,
                    date=headers.date,
                    match_types=match_types,
                    common_subject_words=common_words,
                    header_similarities=header_sims
                )
                similarities.append(result)
        
        # Sort by similarity score
        similarities.sort(key=lambda x: x.similarity_score, reverse=True)
        return similarities[:top_k]
    
    def find_by_subject_similarity(self, query_subject: str, top_k: int = 15) -> List[HeaderSimilarityResult]:
        """Find emails with similar subjects"""
        query_words = set(self.extractor._extract_subject_words(query_subject))
        query_keywords = set(self.extractor._extract_subject_keywords(query_subject))
        
        similarities = []
        
        for headers in self.email_headers:
            subject_words = set(headers.subject_words)
            subject_keywords = set(headers.subject_keywords)
            
            # Calculate word overlap
            word_overlap = len(query_words & subject_words)
            keyword_overlap = len(query_keywords & subject_keywords)
            
            if word_overlap > 0 or keyword_overlap > 0:
                # Calculate similarity score
                word_score = word_overlap / max(len(query_words), 1) if query_words else 0
                keyword_score = keyword_overlap / max(len(query_keywords), 1) if query_keywords else 0
                similarity_score = (word_score * 0.6) + (keyword_score * 0.4)
                
                match_types = []
                if word_overlap > 0:
                    match_types.append(f"Subject words ({word_overlap} common)")
                if keyword_overlap > 0:
                    match_types.append(f"Keywords ({keyword_overlap} common)")
                
                result = HeaderSimilarityResult(
                    email_id=headers.email_id,
                    similarity_score=similarity_score,
                    subject=headers.subject,
                    sender=headers.sender,
                    sender_domain=headers.sender_domain,
                    date=headers.date,
                    match_types=match_types,
                    common_subject_words=list(query_words & subject_words),
                    header_similarities={}
                )
                similarities.append(result)
        
        # Sort by similarity score
        similarities.sort(key=lambda x: x.similarity_score, reverse=True)
        return similarities[:top_k]
    
    def find_by_sender_domain(self, domain: str, top_k: int = 20) -> List[HeaderSimilarityResult]:
        """Find emails from a specific sender domain"""
        results = []
        
        for headers in self.email_headers:
            if domain.lower() in headers.sender_domain.lower():
                result = HeaderSimilarityResult(
                    email_id=headers.email_id,
                    similarity_score=1.0,  # Exact domain match
                    subject=headers.subject,
                    sender=headers.sender,
                    sender_domain=headers.sender_domain,
                    date=headers.date,
                    match_types=[f"Sender domain: {domain}"],
                    common_subject_words=[],
                    header_similarities={}
                )
                results.append(result)
        
        return results[:top_k]
    
    def _calculate_header_similarity(self, headers1: EmailHeaders, headers2: EmailHeaders) -> Tuple[float, List[str], List[str], Dict[str, str]]:
        """Calculate similarity between two email headers"""
        similarity_score = 0.0
        match_types = []
        common_words = []
        header_similarities = {}
        
        # Subject similarity (40% weight)
        subject_words1 = set(headers1.subject_words)
        subject_words2 = set(headers2.subject_words)
        common_subject_words = subject_words1 & subject_words2
        
        if common_subject_words:
            subject_similarity = len(common_subject_words) / max(len(subject_words1), len(subject_words2))
            similarity_score += subject_similarity * 0.4
            match_types.append(f"Subject similarity ({len(common_subject_words)} common words)")
            common_words = list(common_subject_words)
            header_similarities["subject"] = f"{len(common_subject_words)} common words"
        
        # Sender domain similarity (25% weight)
        if headers1.sender_domain and headers2.sender_domain:
            if headers1.sender_domain == headers2.sender_domain:
                similarity_score += 0.25
                match_types.append("Same sender domain")
                header_similarities["sender_domain"] = "Exact match"
            elif self._domains_similar(headers1.sender_domain, headers2.sender_domain):
                similarity_score += 0.15
                match_types.append("Similar sender domain")
                header_similarities["sender_domain"] = "Similar"
        
        # Keyword similarity (20% weight)
        keywords1 = set(headers1.subject_keywords)
        keywords2 = set(headers2.subject_keywords)
        common_keywords = keywords1 & keywords2
        
        if common_keywords:
            keyword_similarity = len(common_keywords) / max(len(keywords1), len(keywords2))
            similarity_score += keyword_similarity * 0.2
            match_types.append(f"Common keywords ({len(common_keywords)})")
            header_similarities["keywords"] = f"{len(common_keywords)} common"
        
        # Content type similarity (10% weight)
        if headers1.content_type and headers2.content_type:
            if headers1.content_type.lower() == headers2.content_type.lower():
                similarity_score += 0.1
                match_types.append("Same content type")
                header_similarities["content_type"] = "Match"
        
        # Date proximity (5% weight)
        if headers1.date and headers2.date:
            if self._dates_close(headers1.date, headers2.date):
                similarity_score += 0.05
                match_types.append("Similar date")
                header_similarities["date"] = "Close dates"
        
        return similarity_score, match_types, common_words, header_similarities
    
    def _domains_similar(self, domain1: str, domain2: str) -> bool:
        """Check if two domains are similar"""
        # Remove common prefixes
        d1 = re.sub(r'^(www\.|mail\.|smtp\.)', '', domain1.lower())
        d2 = re.sub(r'^(www\.|mail\.|smtp\.)', '', domain2.lower())
        
        # Check if one is subdomain of other
        if d1 in d2 or d2 in d1:
            return True
        
        # Check if they share the same base domain
        parts1 = d1.split('.')
        parts2 = d2.split('.')
        
        if len(parts1) >= 2 and len(parts2) >= 2:
            base1 = '.'.join(parts1[-2:])
            base2 = '.'.join(parts2[-2:])
            return base1 == base2
        
        return False
    
    def _dates_close(self, date1: str, date2: str) -> bool:
        """Check if two dates are close (simple heuristic)"""
        try:
            # Extract year and month for simple comparison
            year1 = re.search(r'(\d{4})', date1)
            year2 = re.search(r'(\d{4})', date2)
            
            if year1 and year2:
                return abs(int(year1.group(1)) - int(year2.group(1))) <= 1
            
            return False
        except:
            return False
    
    def analyze_header_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in email headers"""
        if not self.email_headers:
            return {"error": "Index not built"}
        
        # Count patterns
        domain_counts = Counter()
        keyword_counts = Counter()
        content_type_counts = Counter()
        subject_word_counts = Counter()
        
        for headers in self.email_headers:
            # Count domains
            if headers.sender_domain:
                domain_counts[headers.sender_domain] += 1
            
            # Count keywords
            for keyword in headers.subject_keywords:
                keyword_counts[keyword] += 1
            
            # Count content types
            if headers.content_type:
                content_type_counts[headers.content_type] += 1
            
            # Count subject words
            for word in headers.subject_words:
                subject_word_counts[word] += 1
        
        return {
            "total_emails": len(self.email_headers),
            "top_sender_domains": domain_counts.most_common(15),
            "top_subject_keywords": keyword_counts.most_common(15),
            "top_content_types": content_type_counts.most_common(10),
            "top_subject_words": subject_word_counts.most_common(20),
            "emails_with_keywords": sum(1 for h in self.email_headers if h.subject_keywords),
            "unique_domains": len(domain_counts),
            "unique_keywords": len(keyword_counts)
        }
    
    def _get_index_stats(self) -> Dict[str, Any]:
        """Get statistics about the built index"""
        return {
            "total_emails": len(self.email_headers),
            "unique_sender_domains": len(self.domain_index),
            "unique_subject_words": len(self.subject_index),
            "unique_keywords": len(self.keyword_index),
            "unique_senders": len(self.sender_index)
        }


def display_similarity_results(results: List[HeaderSimilarityResult], title: str):
    """Display similarity results in a formatted CLI output"""
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}")
    
    if not results:
        print("No similar emails found.")
        return
    
    print(f"Found {len(results)} similar emails:")
    print("-" * 80)
    
    for i, result in enumerate(results, 1):
        print(f"\n{i:2d}. Email ID: {result.email_id}")
        print(f"    📧 Subject: {result.subject[:65]}...")
        print(f"    👤 Sender:  {result.sender[:65]}...")
        print(f"    🌐 Domain:  {result.sender_domain}")
        print(f"    📅 Date:    {result.date[:30]}...")
        print(f"    📊 Score:   {result.similarity_score:.3f}")
        print(f"    🎯 Matches: {', '.join(result.match_types)}")
        
        if result.common_subject_words:
            print(f"    🔤 Common:  {', '.join(result.common_subject_words[:8])}")
        
        if result.header_similarities:
            similarities = [f"{k}:{v}" for k, v in result.header_similarities.items()]
            print(f"    🔍 Details: {', '.join(similarities)}")


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="Retrieve similar phishing emails based on headers")
    parser.add_argument("--data-dir", default="data/decoded_emails", help="Directory containing decoded emails")
    parser.add_argument("--email-id", help="Find emails similar to this email ID")
    parser.add_argument("--subject", help="Find emails with similar subjects")
    parser.add_argument("--domain", help="Find emails from this sender domain")
    parser.add_argument("--top-k", type=int, default=10, help="Number of results to return")
    parser.add_argument("--analyze", action="store_true", help="Analyze header patterns")
    parser.add_argument("--interactive", action="store_true", help="Run interactive mode")
    
    args = parser.parse_args()
    
    # Initialize retriever
    print("🚀 Initializing Header Similarity Retriever...")
    retriever = HeaderSimilarityRetriever(args.data_dir)
    
    # Build index
    print("📊 Building header index...")
    stats = retriever.build_index()
    
    print(f"\n✅ Index built successfully!")
    print(f"   Total emails: {stats['total_emails']}")
    print(f"   Unique sender domains: {stats['unique_sender_domains']}")
    print(f"   Unique subject words: {stats['unique_subject_words']}")
    print(f"   Unique keywords: {stats['unique_keywords']}")
    
    # Handle different modes
    if args.analyze:
        print("\n📈 Analyzing header patterns...")
        patterns = retriever.analyze_header_patterns()
        
        print(f"\n📊 Header Pattern Analysis:")
        print(f"   Total emails: {patterns['total_emails']}")
        print(f"   Emails with keywords: {patterns['emails_with_keywords']}")
        print(f"   Unique domains: {patterns['unique_domains']}")
        print(f"   Unique keywords: {patterns['unique_keywords']}")
        
        print(f"\n🌐 Top 10 Sender Domains:")
        for i, (domain, count) in enumerate(patterns['top_sender_domains'][:10], 1):
            percentage = (count / patterns['total_emails']) * 100
            print(f"   {i:2d}. {domain:<30} {count:4d} emails ({percentage:5.1f}%)")
        
        print(f"\n🔤 Top 10 Subject Keywords:")
        for i, (keyword, count) in enumerate(patterns['top_subject_keywords'][:10], 1):
            percentage = (count / patterns['total_emails']) * 100
            print(f"   {i:2d}. {keyword:<20} {count:4d} emails ({percentage:5.1f}%)")
        
        print(f"\n📝 Top 10 Subject Words:")
        for i, (word, count) in enumerate(patterns['top_subject_words'][:10], 1):
            percentage = (count / patterns['total_emails']) * 100
            print(f"   {i:2d}. {word:<20} {count:4d} emails ({percentage:5.1f}%)")
    
    elif args.email_id:
        try:
            results = retriever.find_similar_by_headers(args.email_id, args.top_k)
            display_similarity_results(results, f"EMAILS SIMILAR TO: {args.email_id}")
        except ValueError as e:
            print(f"❌ Error: {e}")
    
    elif args.subject:
        results = retriever.find_by_subject_similarity(args.subject, args.top_k)
        display_similarity_results(results, f"EMAILS WITH SIMILAR SUBJECT TO: '{args.subject}'")
    
    elif args.domain:
        results = retriever.find_by_sender_domain(args.domain, args.top_k)
        display_similarity_results(results, f"EMAILS FROM DOMAIN: {args.domain}")
    
    elif args.interactive:
        # Interactive mode
        while True:
            print("\n" + "="*50)
            print("📋 HEADER SIMILARITY SEARCH MENU")
            print("="*50)
            print("1. 🔍 Find similar emails by email ID")
            print("2. 📧 Find emails with similar subjects")
            print("3. 🌐 Find emails from specific domain")
            print("4. 📈 Analyze header patterns")
            print("0. 🚪 Exit")
            
            choice = input("\nEnter your choice (0-4): ").strip()
            
            if choice == "0":
                print("👋 Goodbye!")
                break
            elif choice == "1":
                email_id = input("Enter email ID: ").strip()
                if email_id:
                    try:
                        results = retriever.find_similar_by_headers(email_id, args.top_k)
                        display_similarity_results(results, f"EMAILS SIMILAR TO: {email_id}")
                    except ValueError as e:
                        print(f"❌ Error: {e}")
            elif choice == "2":
                subject = input("Enter subject to search for: ").strip()
                if subject:
                    results = retriever.find_by_subject_similarity(subject, args.top_k)
                    display_similarity_results(results, f"EMAILS WITH SIMILAR SUBJECT TO: '{subject}'")
            elif choice == "3":
                domain = input("Enter sender domain: ").strip()
                if domain:
                    results = retriever.find_by_sender_domain(domain, args.top_k)
                    display_similarity_results(results, f"EMAILS FROM DOMAIN: {domain}")
            elif choice == "4":
                patterns = retriever.analyze_header_patterns()
                print(f"\n📊 Header Pattern Analysis:")
                print(f"   Total emails: {patterns['total_emails']}")
                print(f"   Emails with keywords: {patterns['emails_with_keywords']}")
                print(f"   Unique domains: {patterns['unique_domains']}")
                
                print(f"\n🌐 Top 5 Sender Domains:")
                for i, (domain, count) in enumerate(patterns['top_sender_domains'][:5], 1):
                    print(f"   {i}. {domain} ({count} emails)")
                
                print(f"\n🔤 Top 5 Subject Keywords:")
                for i, (keyword, count) in enumerate(patterns['top_subject_keywords'][:5], 1):
                    print(f"   {i}. {keyword} ({count} emails)")
            else:
                print("❌ Invalid choice. Please try again.")
    
    else:
        print("\n💡 Usage examples:")
        print("   python3 header_similarity_retrieval.py --email-id sample-123")
        print("   python3 header_similarity_retrieval.py --subject 'urgent account verification'")
        print("   python3 header_similarity_retrieval.py --domain gmail.com")
        print("   python3 header_similarity_retrieval.py --analyze")
        print("   python3 header_similarity_retrieval.py --interactive")


if __name__ == "__main__":
    main()
