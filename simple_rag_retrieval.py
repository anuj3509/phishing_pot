#!/usr/bin/env python3
"""
Simple Local RAG Retrieval System for Phishing Emails

This system extracts PHISHING ANALYSIS sections from decoded emails and implements
simple hybrid search for finding similar phishing emails using basic Python libraries.
"""

import os
import re
import json
import math
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from collections import defaultdict, Counter


@dataclass
class PhishingAnalysis:
    """Structure for phishing analysis data"""
    email_id: str
    urgency_words: List[str]
    suspicious_phrases: List[str]
    urls: List[str]
    domains: List[str]
    subject: str
    sender: str
    sender_domain: str
    content_preview: str
    analysis_text: str


@dataclass
class RetrievalResult:
    """Structure for retrieval results"""
    email_id: str
    similarity_score: float
    keyword_score: float
    subject: str
    sender: str
    urgency_words: List[str]
    suspicious_phrases: List[str]
    urls: List[str]
    domains: List[str]
    match_reasons: List[str]


class SimplePhishingAnalysisExtractor:
    """Extracts and parses PHISHING ANALYSIS sections from decoded emails"""
    
    def __init__(self):
        self.urgency_patterns = [
            'urgent', 'immediately', 'expire', 'expires', 'expiring', 
            'suspend', 'suspended', 'verify', 'confirm', 'update',
            'act now', 'limited time', 'final notice', 'last chance'
        ]
        
        self.suspicious_patterns = [
            'click here', 'verify your account', 'update your information',
            'confirm your identity', 'suspended account', 'unusual activity',
            'security alert', 'immediate action required'
        ]
    
    def extract_analysis_section(self, file_path: str) -> Optional[PhishingAnalysis]:
        """Extract PHISHING ANALYSIS section from a decoded email file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find PHISHING ANALYSIS section
            analysis_start = content.find('PHISHING ANALYSIS:')
            if analysis_start == -1:
                return None
            
            # Find the end of the section
            analysis_end = content.find('DECODED TEXT CONTENT:', analysis_start)
            if analysis_end == -1:
                analysis_end = content.find('DECODED HTML CONTENT:', analysis_start)
            if analysis_end == -1:
                analysis_end = len(content)
            
            analysis_section = content[analysis_start:analysis_end].strip()
            
            # Extract email metadata from headers section
            headers_start = content.find('HEADERS:')
            headers_end = content.find('ENCODING INFORMATION:', headers_start)
            headers_section = content[headers_start:headers_end] if headers_start != -1 else ""
            
            # Parse headers
            subject = self._extract_header_value(headers_section, 'Subject:')
            sender = self._extract_header_value(headers_section, 'From:')
            sender_domain = self._extract_sender_domain(sender)
            
            # Extract content preview
            content_start = content.find('DECODED TEXT CONTENT:')
            content_preview = ""
            if content_start != -1:
                content_text = content[content_start:content_start + 500]
                lines = content_text.split('\n')[2:5]  # Skip header lines
                content_preview = ' '.join(lines).strip()[:200]
            
            # Parse analysis section
            urgency_words = self._extract_urgency_words(analysis_section)
            suspicious_phrases = self._extract_suspicious_phrases(analysis_section)
            urls = self._extract_urls(analysis_section)
            domains = self._extract_domains(urls)
            
            email_id = Path(file_path).stem
            
            return PhishingAnalysis(
                email_id=email_id,
                urgency_words=urgency_words,
                suspicious_phrases=suspicious_phrases,
                urls=urls,
                domains=domains,
                subject=subject,
                sender=sender,
                sender_domain=sender_domain,
                content_preview=content_preview,
                analysis_text=analysis_section
            )
            
        except Exception as e:
            print(f"Error extracting analysis from {file_path}: {str(e)}")
            return None
    
    def _extract_header_value(self, headers: str, header_name: str) -> str:
        """Extract a specific header value"""
        try:
            pattern = f'{header_name}\\s*(.+?)\\n'
            match = re.search(pattern, headers, re.IGNORECASE)
            return match.group(1).strip() if match else ""
        except:
            return ""
    
    def _extract_sender_domain(self, sender: str) -> str:
        """Extract domain from sender email"""
        try:
            if '@' in sender:
                domain = sender.split('@')[-1].strip('>')
                return domain.lower()
            return ""
        except:
            return ""
    
    def _extract_urgency_words(self, analysis_text: str) -> List[str]:
        """Extract urgency words from analysis text"""
        urgency_words = []
        
        # Look for explicit urgency words section
        urgency_match = re.search(r'Urgency words found:\s*(.+?)(?:\n|$)', analysis_text, re.IGNORECASE)
        if urgency_match:
            words = urgency_match.group(1).split(',')
            urgency_words.extend([w.strip() for w in words if w.strip()])
        
        # Also scan for common urgency patterns
        text_lower = analysis_text.lower()
        for pattern in self.urgency_patterns:
            if pattern.lower() in text_lower:
                urgency_words.append(pattern)
        
        return list(set(urgency_words))
    
    def _extract_suspicious_phrases(self, analysis_text: str) -> List[str]:
        """Extract suspicious phrases from analysis text"""
        suspicious_phrases = []
        
        # Look for explicit suspicious phrases section
        suspicious_match = re.search(r'Suspicious phrases:\s*(.+?)(?:\n|$)', analysis_text, re.IGNORECASE)
        if suspicious_match:
            phrases = suspicious_match.group(1).split(',')
            suspicious_phrases.extend([p.strip() for p in phrases if p.strip()])
        
        # Scan for common suspicious patterns
        text_lower = analysis_text.lower()
        for pattern in self.suspicious_patterns:
            if pattern.lower() in text_lower:
                suspicious_phrases.append(pattern)
        
        return list(set(suspicious_phrases))
    
    def _extract_urls(self, analysis_text: str) -> List[str]:
        """Extract URLs from analysis text"""
        urls = []
        
        # Find URLs section
        urls_start = analysis_text.find('URLs found:')
        if urls_start == -1:
            return urls
        
        # Extract URLs (lines starting with "  - ")
        lines = analysis_text[urls_start:].split('\n')
        for line in lines:
            if line.strip().startswith('- '):
                url = line.strip()[2:].strip()
                if url and not url.startswith('DECODED'):
                    urls.append(url)
        
        return urls
    
    def _extract_domains(self, urls: List[str]) -> List[str]:
        """Extract domains from URLs"""
        domains = []
        for url in urls:
            try:
                if '://' in url:
                    domain = url.split('://')[1].split('/')[0].split('?')[0]
                elif url.endswith('.com') or url.endswith('.org') or url.endswith('.net'):
                    domain = url.split('/')[0].split('?')[0]
                else:
                    continue
                
                # Clean domain
                domain = domain.lower().strip()
                if domain and '.' in domain:
                    domains.append(domain)
            except:
                continue
        
        return list(set(domains))


class SimpleHybridRetriever:
    """Simple hybrid retrieval system using basic text matching and keyword scoring"""
    
    def __init__(self, data_dir: str = "data/decoded_emails"):
        """Initialize the simple retriever"""
        self.data_dir = Path(data_dir)
        self.extractor = SimplePhishingAnalysisExtractor()
        
        # Storage
        self.phishing_analyses: List[PhishingAnalysis] = []
        self.domain_index: Dict[str, List[int]] = defaultdict(list)
        self.urgency_index: Dict[str, List[int]] = defaultdict(list)
        self.word_index: Dict[str, List[int]] = defaultdict(list)
        
        print(f"Initialized SimpleHybridRetriever for directory: {data_dir}")
    
    def build_index(self) -> Dict[str, Any]:
        """Build the retrieval index from decoded emails"""
        print("Building retrieval index...")
        
        # Find all decoded email files
        email_files = list(self.data_dir.glob("*.txt"))
        print(f"Found {len(email_files)} decoded email files")
        
        # Extract phishing analyses
        analyses = []
        failed_count = 0
        
        for email_file in email_files:
            analysis = self.extractor.extract_analysis_section(str(email_file))
            if analysis:
                analyses.append(analysis)
            else:
                failed_count += 1
        
        self.phishing_analyses = analyses
        print(f"Extracted {len(analyses)} phishing analyses, {failed_count} failed")
        
        if not analyses:
            raise ValueError("No phishing analyses extracted. Check your data directory.")
        
        # Build indexes
        self._build_indexes()
        
        print("Index built successfully")
        return self._get_index_stats()
    
    def _build_indexes(self):
        """Build auxiliary indexes for fast retrieval"""
        self.domain_index = defaultdict(list)
        self.urgency_index = defaultdict(list)
        self.word_index = defaultdict(list)
        
        for i, analysis in enumerate(self.phishing_analyses):
            # Index by domains
            for domain in analysis.domains:
                self.domain_index[domain.lower()].append(i)
            
            # Index by urgency words
            for word in analysis.urgency_words:
                self.urgency_index[word.lower()].append(i)
            
            # Index by all words in subject and content
            all_text = f"{analysis.subject} {analysis.content_preview} {' '.join(analysis.urgency_words)} {' '.join(analysis.suspicious_phrases)}"
            words = re.findall(r'\b\w+\b', all_text.lower())
            for word in set(words):
                if len(word) > 2:  # Skip very short words
                    self.word_index[word].append(i)
    
    def simple_search(self, query: str, top_k: int = 10,
                     domain_filter: Optional[str] = None,
                     urgency_filter: Optional[str] = None) -> List[RetrievalResult]:
        """
        Perform simple hybrid search using keyword matching and scoring
        
        Args:
            query: Search query
            top_k: Number of results to return
            domain_filter: Filter by specific domain
            urgency_filter: Filter by urgency word
            
        Returns:
            List of retrieval results
        """
        if not self.phishing_analyses:
            raise ValueError("Index not built. Call build_index() first.")
        
        # Get candidate indices (for filtering)
        candidate_indices = set(range(len(self.phishing_analyses)))
        
        # Apply domain filter
        if domain_filter:
            domain_candidates = set()
            for domain, indices in self.domain_index.items():
                if domain_filter.lower() in domain:
                    domain_candidates.update(indices)
            candidate_indices &= domain_candidates
        
        # Apply urgency filter
        if urgency_filter:
            urgency_candidates = set()
            for urgency, indices in self.urgency_index.items():
                if urgency_filter.lower() in urgency:
                    urgency_candidates.update(indices)
            candidate_indices &= urgency_candidates
        
        if not candidate_indices:
            return []
        
        # Score candidates
        query_words = set(re.findall(r'\b\w+\b', query.lower()))
        scored_results = []
        
        for i in candidate_indices:
            analysis = self.phishing_analyses[i]
            score = self._calculate_similarity_score(query_words, analysis)
            
            if score > 0:  # Only include results with some similarity
                match_reasons = self._determine_match_reasons(query, analysis)
                
                result = RetrievalResult(
                    email_id=analysis.email_id,
                    similarity_score=score,
                    keyword_score=score,
                    subject=analysis.subject,
                    sender=analysis.sender,
                    urgency_words=analysis.urgency_words,
                    suspicious_phrases=analysis.suspicious_phrases,
                    urls=analysis.urls,
                    domains=analysis.domains,
                    match_reasons=match_reasons
                )
                scored_results.append(result)
        
        # Sort by score and return top results
        scored_results.sort(key=lambda x: x.similarity_score, reverse=True)
        return scored_results[:top_k]
    
    def _calculate_similarity_score(self, query_words: set, analysis: PhishingAnalysis) -> float:
        """Calculate similarity score between query and analysis"""
        score = 0.0
        
        # Create text from analysis
        analysis_text = f"{analysis.subject} {analysis.content_preview} {' '.join(analysis.urgency_words)} {' '.join(analysis.suspicious_phrases)}"
        analysis_words = set(re.findall(r'\b\w+\b', analysis_text.lower()))
        
        # Calculate word overlap
        common_words = query_words & analysis_words
        if not query_words:
            return 0.0
        
        # Base score from word overlap
        overlap_score = len(common_words) / len(query_words)
        score += overlap_score * 0.5
        
        # Bonus for matches in subject
        subject_words = set(re.findall(r'\b\w+\b', analysis.subject.lower()))
        subject_matches = query_words & subject_words
        if subject_matches:
            score += (len(subject_matches) / len(query_words)) * 0.3
        
        # Bonus for urgency word matches
        urgency_words = set(word.lower() for word in analysis.urgency_words)
        urgency_matches = query_words & urgency_words
        if urgency_matches:
            score += (len(urgency_matches) / len(query_words)) * 0.2
        
        # Bonus for domain matches
        query_str = ' '.join(query_words)
        for domain in analysis.domains:
            if domain.lower() in query_str:
                score += 0.1
        
        return min(score, 1.0)  # Cap at 1.0
    
    def find_similar_by_analysis(self, email_id: str, top_k: int = 10) -> List[RetrievalResult]:
        """Find emails similar to a specific email"""
        # Find the target analysis
        target_analysis = None
        for analysis in self.phishing_analyses:
            if analysis.email_id == email_id:
                target_analysis = analysis
                break
        
        if not target_analysis:
            raise ValueError(f"Email {email_id} not found in index")
        
        # Create query from target analysis
        query_parts = []
        query_parts.extend(target_analysis.urgency_words)
        query_parts.extend(target_analysis.suspicious_phrases[:3])  # Limit to first 3
        query_parts.extend(target_analysis.domains[:2])  # Limit to first 2
        
        # Add some words from subject
        subject_words = re.findall(r'\b\w+\b', target_analysis.subject.lower())
        query_parts.extend(subject_words[:5])  # First 5 words from subject
        
        query = ' '.join(query_parts)
        
        # Search and exclude the original email
        results = self.simple_search(query, top_k + 1)
        return [r for r in results if r.email_id != email_id][:top_k]
    
    def find_by_domain_cluster(self, domain: str, top_k: int = 20) -> List[RetrievalResult]:
        """Find emails that use a specific domain"""
        results = []
        
        for i, analysis in enumerate(self.phishing_analyses):
            if any(domain.lower() in d.lower() for d in analysis.domains):
                result = RetrievalResult(
                    email_id=analysis.email_id,
                    similarity_score=1.0,
                    keyword_score=1.0,
                    subject=analysis.subject,
                    sender=analysis.sender,
                    urgency_words=analysis.urgency_words,
                    suspicious_phrases=analysis.suspicious_phrases,
                    urls=analysis.urls,
                    domains=analysis.domains,
                    match_reasons=[f"Contains domain: {domain}"]
                )
                results.append(result)
        
        return results[:top_k]
    
    def analyze_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in the phishing email collection"""
        if not self.phishing_analyses:
            return {"error": "Index not built"}
        
        # Count patterns
        domain_counts = Counter()
        urgency_counts = Counter()
        phrase_counts = Counter()
        sender_domain_counts = Counter()
        
        for analysis in self.phishing_analyses:
            # Count domains
            for domain in analysis.domains:
                domain_counts[domain] += 1
            
            # Count urgency words
            for word in analysis.urgency_words:
                urgency_counts[word] += 1
            
            # Count suspicious phrases
            for phrase in analysis.suspicious_phrases:
                phrase_counts[phrase] += 1
            
            # Count sender domains
            if analysis.sender_domain:
                sender_domain_counts[analysis.sender_domain] += 1
        
        return {
            "total_emails": len(self.phishing_analyses),
            "top_domains": domain_counts.most_common(20),
            "top_urgency_words": urgency_counts.most_common(15),
            "top_suspicious_phrases": phrase_counts.most_common(15),
            "top_sender_domains": sender_domain_counts.most_common(15),
            "emails_with_urls": sum(1 for a in self.phishing_analyses if a.urls),
            "emails_with_urgency": sum(1 for a in self.phishing_analyses if a.urgency_words),
            "emails_with_suspicious_phrases": sum(1 for a in self.phishing_analyses if a.suspicious_phrases)
        }
    
    def _determine_match_reasons(self, query: str, analysis: PhishingAnalysis) -> List[str]:
        """Determine why an email matched the query"""
        reasons = []
        query_lower = query.lower()
        
        # Check for direct keyword matches
        if any(word.lower() in query_lower for word in analysis.urgency_words):
            reasons.append("Matching urgency words")
        
        if any(phrase.lower() in query_lower for phrase in analysis.suspicious_phrases):
            reasons.append("Matching suspicious phrases")
        
        if any(domain.lower() in query_lower for domain in analysis.domains):
            reasons.append("Matching domains")
        
        if analysis.sender_domain and analysis.sender_domain.lower() in query_lower:
            reasons.append("Matching sender domain")
        
        # Check for subject matches
        subject_words = set(re.findall(r'\b\w+\b', analysis.subject.lower()))
        query_words = set(re.findall(r'\b\w+\b', query_lower))
        if subject_words & query_words:
            reasons.append("Subject similarity")
        
        return reasons or ["General keyword similarity"]
    
    def _get_index_stats(self) -> Dict[str, Any]:
        """Get statistics about the built index"""
        return {
            "total_emails": len(self.phishing_analyses),
            "unique_domains": len(self.domain_index),
            "unique_urgency_words": len(self.urgency_index),
            "unique_words": len(self.word_index)
        }


def main():
    """Demonstration of the simple RAG retrieval system"""
    print("=" * 70)
    print("  Simple Local RAG Retrieval System for Phishing Emails")
    print("=" * 70)
    
    try:
        # Initialize retriever
        print("\n🚀 Initializing simple retrieval system...")
        retriever = SimpleHybridRetriever()
        
        # Build index
        print("📊 Building retrieval index...")
        stats = retriever.build_index()
        
        print(f"\n✅ Index built successfully!")
        print(f"   Total emails: {stats['total_emails']}")
        print(f"   Unique domains: {stats['unique_domains']}")
        print(f"   Unique urgency words: {stats['unique_urgency_words']}")
        print(f"   Unique words indexed: {stats['unique_words']}")
        
        # Pattern analysis
        print("\n📈 Analyzing phishing patterns...")
        patterns = retriever.analyze_patterns()
        
        print(f"   Emails with URLs: {patterns['emails_with_urls']}")
        print(f"   Emails with urgency words: {patterns['emails_with_urgency']}")
        print(f"   Emails with suspicious phrases: {patterns['emails_with_suspicious_phrases']}")
        
        print("\n🔝 Top patterns found:")
        print("   Top domains:", [f"{d}({c})" for d, c in patterns['top_domains'][:5]])
        print("   Top urgency words:", [f"{w}({c})" for w, c in patterns['top_urgency_words'][:5]])
        
        # Example searches
        print("\n🔍 Testing retrieval with example queries:")
        
        test_queries = [
            "banking verification urgent expire",
            "PayPal account suspended verify",
            "Microsoft security alert",
            "urgent action required account"
        ]
        
        for query in test_queries:
            print(f"\n   Query: '{query}'")
            results = retriever.simple_search(query, top_k=3)
            
            for i, result in enumerate(results, 1):
                print(f"      {i}. {result.email_id} (score: {result.similarity_score:.3f})")
                print(f"         Subject: {result.subject[:60]}...")
                print(f"         Reasons: {', '.join(result.match_reasons)}")
                if result.urgency_words:
                    print(f"         Urgency: {', '.join(result.urgency_words[:3])}")
        
        print("\n✅ Simple RAG retrieval system ready!")
        print("   Run 'python3 test_rag_retrieval.py' for interactive testing")
        
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
