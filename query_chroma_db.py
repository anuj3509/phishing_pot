#!/usr/bin/env python3
"""
Query ChromaDB for Phishing Emails

This script queries the ChromaDB vector database for specific substrings
and patterns using Voyage-3 embeddings.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any

try:
    import chromadb
    from chromadb.config import Settings
except ImportError:
    print("❌ ChromaDB not available. Install with: pip install chromadb")
    sys.exit(1)

try:
    import voyageai
except ImportError:
    print("❌ VoyageAI not available. Install with: pip install voyageai")
    sys.exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # Environment variables should still work


class ChromaDBQuerier:
    """Query ChromaDB vector database for phishing emails"""
    
    def __init__(self, db_path: str = "./simple_chroma_db"):
        self.db_path = Path(db_path)
        
        if not self.db_path.exists():
            raise ValueError(f"ChromaDB not found at {db_path}. Run simple_chroma_setup.py first.")
        
        # Initialize Voyage client
        voyage_key = os.getenv('VOYAGE_API_KEY')
        if not voyage_key:
            raise ValueError("VOYAGE_API_KEY not found in environment variables")
        
        self.voyage_client = voyageai.Client(api_key=voyage_key)
        
        # Initialize ChromaDB
        self.client = chromadb.PersistentClient(
            path=str(self.db_path),
            settings=Settings(anonymized_telemetry=False)
        )
        
        try:
            self.collection = self.client.get_collection("phishing_emails")
            print(f"✅ Connected to ChromaDB with {self.collection.count()} emails")
        except Exception as e:
            raise ValueError(f"Could not access collection 'phishing_emails': {e}")
    
    def query_similarity(self, query: str, n_results: int = 10) -> Dict[str, Any]:
        """Query using semantic similarity"""
        try:
            print(f"🔍 Generating embedding for query: '{query}'")
            
            # Generate query embedding
            result = self.voyage_client.embed(
                texts=[query],
                model="voyage-3",
                input_type="query"
            )
            
            query_embedding = result.embeddings[0]
            
            # Search in ChromaDB
            print(f"📊 Searching ChromaDB for {n_results} most similar emails...")
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results
            )
            
            return {
                "query": query,
                "count": len(results["ids"][0]) if results["ids"] else 0,
                "results": results
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def query_metadata(self, where_clause: Dict[str, Any], n_results: int = 20) -> Dict[str, Any]:
        """Query using metadata filters"""
        try:
            print(f"🔍 Querying metadata with filter: {where_clause}")
            
            results = self.collection.get(
                where=where_clause,
                limit=n_results
            )
            
            return {
                "filter": where_clause,
                "count": len(results["ids"]) if results["ids"] else 0,
                "results": results
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def display_similarity_results(self, results: Dict[str, Any]):
        """Display similarity search results"""
        if "error" in results:
            print(f"❌ Error: {results['error']}")
            return
        
        if results["count"] == 0:
            print("❌ No results found")
            return
        
        print(f"\n📊 Found {results['count']} similar emails:")
        print("=" * 80)
        
        for i, (email_id, metadata, distance, document) in enumerate(zip(
            results["results"]["ids"][0],
            results["results"]["metadatas"][0],
            results["results"]["distances"][0],
            results["results"]["documents"][0]
        ), 1):
            similarity = 1 - distance
            
            print(f"\n{i:2d}. Email ID: {email_id}")
            print(f"    📧 Subject: {metadata.get('subject', 'N/A')[:70]}...")
            print(f"    👤 Sender:  {metadata.get('sender', 'N/A')[:50]}...")
            print(f"    📅 Date:    {metadata.get('date', 'N/A')[:30]}...")
            print(f"    📊 Similarity: {similarity:.3f}")
            print(f"    🌐 URLs: {metadata.get('url_count', 0)}")
            print(f"    ⚡ Urgency words: {metadata.get('urgency_count', 0)}")
            print(f"    📝 Content preview: {document[:100]}...")
    
    def display_metadata_results(self, results: Dict[str, Any]):
        """Display metadata search results"""
        if "error" in results:
            print(f"❌ Error: {results['error']}")
            return
        
        if results["count"] == 0:
            print("❌ No results found")
            return
        
        print(f"\n📊 Found {results['count']} matching emails:")
        print("=" * 80)
        
        for i, (email_id, metadata) in enumerate(zip(
            results["results"]["ids"],
            results["results"]["metadatas"]
        ), 1):
            print(f"\n{i:2d}. Email ID: {email_id}")
            print(f"    📧 Subject: {metadata.get('subject', 'N/A')[:70]}...")
            print(f"    👤 Sender:  {metadata.get('sender', 'N/A')[:50]}...")
            print(f"    📅 Date:    {metadata.get('date', 'N/A')[:30]}...")
            print(f"    🌐 URLs: {metadata.get('url_count', 0)}")
            print(f"    ⚡ Urgency words: {metadata.get('urgency_count', 0)}")
            print(f"    📊 Content length: {metadata.get('content_length', 0)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            count = self.collection.count()
            
            # Get some sample metadata to understand the data
            sample = self.collection.get(limit=10)
            
            # Count metadata patterns
            url_counts = [m.get('url_count', 0) for m in sample['metadatas']]
            urgency_counts = [m.get('urgency_count', 0) for m in sample['metadatas']]
            
            return {
                "total_emails": count,
                "database_path": str(self.db_path),
                "collection_name": self.collection.name,
                "avg_urls_per_email": sum(url_counts) / len(url_counts) if url_counts else 0,
                "avg_urgency_per_email": sum(urgency_counts) / len(urgency_counts) if urgency_counts else 0,
                "emails_with_urls": sum(1 for m in sample['metadatas'] if m.get('has_urls', False)),
                "emails_with_urgency": sum(1 for m in sample['metadatas'] if m.get('has_urgency', False))
            }
        except Exception as e:
            return {"error": str(e)}


def interactive_mode(querier: ChromaDBQuerier):
    """Interactive query mode"""
    print("\n" + "=" * 70)
    print("  🔍 INTERACTIVE CHROMADB QUERY MODE")
    print("=" * 70)
    
    while True:
        print("\n📋 Query Options:")
        print("1. 🎯 Semantic similarity search")
        print("2. 📊 Metadata filter search") 
        print("3. 📈 Database statistics")
        print("4. 💡 Example queries")
        print("0. 🚪 Exit")
        
        choice = input("\nEnter your choice (0-4): ").strip()
        
        if choice == "0":
            print("👋 Goodbye!")
            break
        
        elif choice == "1":
            query = input("Enter search query: ").strip()
            if query:
                try:
                    n_results = int(input("Number of results (default 5): ") or "5")
                except ValueError:
                    n_results = 5
                
                results = querier.query_similarity(query, n_results)
                querier.display_similarity_results(results)
        
        elif choice == "2":
            print("\n📊 Metadata Filter Options:")
            print("1. Find emails with URLs")
            print("2. Find emails with urgency words") 
            print("3. Find emails by sender domain")
            print("4. Custom filter")
            
            filter_choice = input("Choose filter (1-4): ").strip()
            
            if filter_choice == "1":
                results = querier.query_metadata({"has_urls": True}, 10)
                querier.display_metadata_results(results)
            
            elif filter_choice == "2":
                results = querier.query_metadata({"has_urgency": True}, 10)
                querier.display_metadata_results(results)
            
            elif filter_choice == "3":
                domain = input("Enter sender domain to search: ").strip()
                if domain:
                    results = querier.query_metadata({"sender": {"$contains": domain}}, 10)
                    querier.display_metadata_results(results)
            
            elif filter_choice == "4":
                print("Example: {'url_count': {'$gt': 5}} for emails with >5 URLs")
                filter_str = input("Enter filter as JSON: ").strip()
                try:
                    import json
                    where_clause = json.loads(filter_str)
                    results = querier.query_metadata(where_clause, 10)
                    querier.display_metadata_results(results)
                except Exception as e:
                    print(f"❌ Invalid filter: {e}")
        
        elif choice == "3":
            stats = querier.get_stats()
            print(f"\n📊 Database Statistics:")
            for key, value in stats.items():
                if isinstance(value, float):
                    print(f"   {key}: {value:.2f}")
                else:
                    print(f"   {key}: {value}")
        
        elif choice == "4":
            print(f"\n💡 Example Queries:")
            print("   • 'urgent account verification'")
            print("   • 'paypal suspended verify'") 
            print("   • 'microsoft security alert'")
            print("   • 'banking login credentials'")
            print("   • 'cryptocurrency investment opportunity'")
            print("   • 'amazon account locked'")
            print("   • 'tax refund pending'")
        
        else:
            print("❌ Invalid choice. Please try again.")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Query ChromaDB vector database for phishing emails")
    parser.add_argument("--query", help="Semantic similarity search query")
    parser.add_argument("--exact", help="Exact substring to search for (will use similarity)")
    parser.add_argument("--top-k", type=int, default=10, help="Number of results to return")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--stats", action="store_true", help="Show database statistics")
    parser.add_argument("--db-path", default="./simple_chroma_db", help="ChromaDB path")
    
    args = parser.parse_args()
    
    try:
        # Initialize querier
        print("🚀 Connecting to ChromaDB...")
        querier = ChromaDBQuerier(args.db_path)
        
        # Handle different modes
        if args.interactive:
            interactive_mode(querier)
        
        elif args.stats:
            stats = querier.get_stats()
            print(f"\n📊 Database Statistics:")
            for key, value in stats.items():
                if isinstance(value, float):
                    print(f"   {key}: {value:.2f}")
                else:
                    print(f"   {key}: {value}")
        
        elif args.query or args.exact:
            query_text = args.query or args.exact
            print(f"\n🔍 Searching for: '{query_text}'")
            results = querier.query_similarity(query_text, args.top_k)
            querier.display_similarity_results(results)
        
        else:
            # Default: search for "urgent account verification"
            print("\n🔍 Default search: 'urgent account verification'")
            results = querier.query_similarity("urgent account verification", args.top_k)
            querier.display_similarity_results(results)
            
            print("\n" + "-" * 80)
            print("💡 Usage examples:")
            print("   python3 query_chroma_db.py --query 'paypal suspended'")
            print("   python3 query_chroma_db.py --exact 'urgent account verification'")
            print("   python3 query_chroma_db.py --interactive")
            print("   python3 query_chroma_db.py --stats")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
