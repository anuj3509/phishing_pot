#!/usr/bin/env python3
"""
Simple ChromaDB Setup for Phishing Emails

This script creates a basic ChromaDB vector database using the processed emails
with Voyage-3 embeddings, focusing on simplicity and minimal dependencies.
"""

import os
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
import time
from collections import defaultdict

# Check for required imports
try:
    import chromadb
    from chromadb.config import Settings
    print("✅ ChromaDB available")
except ImportError:
    print("❌ ChromaDB not available. Install with: pip install chromadb")
    exit(1)

try:
    import voyageai
    print("✅ VoyageAI available")
except ImportError:
    print("❌ VoyageAI not available. Install with: pip install voyageai")
    exit(1)

try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ Environment loaded")
except ImportError:
    print("⚠️  python-dotenv not available, using environment variables directly")


class SimpleChromaSetup:
    """Simple ChromaDB setup with Voyage embeddings"""
    
    def __init__(self, db_path: str = "./simple_chroma_db"):
        self.db_path = Path(db_path)
        self.db_path.mkdir(exist_ok=True)
        
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
        
        # Create collection
        try:
            self.collection = self.client.get_collection("phishing_emails")
            print("✅ Found existing collection")
        except:
            self.collection = self.client.create_collection(
                name="phishing_emails",
                metadata={"hnsw:space": "cosine"}
            )
            print("✅ Created new collection")
    
    def extract_email_data(self, metadata_file: Path, decoded_file: Path) -> Optional[Dict[str, Any]]:
        """Extract email data from metadata and decoded files"""
        try:
            # Load metadata
            with open(metadata_file, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            
            # Load decoded content
            with open(decoded_file, 'r', encoding='utf-8', errors='ignore') as f:
                decoded_content = f.read()
            
            # Extract headers from decoded content
            headers = {}
            headers_start = decoded_content.find('HEADERS:')
            if headers_start != -1:
                headers_end = decoded_content.find('ENCODING INFORMATION:', headers_start)
                if headers_end == -1:
                    headers_end = decoded_content.find('PHISHING ANALYSIS:', headers_start)
                
                if headers_end != -1:
                    headers_section = decoded_content[headers_start:headers_end]
                    
                    # Parse headers
                    for line in headers_section.split('\n'):
                        if ':' in line and not line.startswith('HEADERS'):
                            key, value = line.split(':', 1)
                            headers[key.strip().lower()] = value.strip()
            
            # Extract phishing analysis
            analysis_data = metadata.get('phishing_analysis', {})
            
            # Extract text content
            text_content = ""
            text_start = decoded_content.find('DECODED TEXT CONTENT:')
            if text_start != -1:
                text_end = decoded_content.find('DECODED HTML CONTENT:', text_start)
                if text_end == -1:
                    text_end = len(decoded_content)
                
                text_section = decoded_content[text_start:text_end]
                lines = text_section.split('\n')[2:]  # Skip header
                text_content = ' '.join(line.strip() for line in lines if line.strip())[:2000]  # Limit length
            
            email_id = metadata_file.stem
            
            return {
                'id': email_id,
                'subject': headers.get('subject', ''),
                'sender': headers.get('from', ''),
                'date': headers.get('date', ''),
                'text_content': text_content,
                'urls': analysis_data.get('urls', []),
                'urgency_words': analysis_data.get('urgency_words', []),
                'suspicious_phrases': analysis_data.get('suspicious_phrases', []),
                'metadata': metadata
            }
            
        except Exception as e:
            print(f"❌ Error extracting data from {metadata_file}: {e}")
            return None
    
    def create_embedding_text(self, email_data: Dict[str, Any]) -> str:
        """Create text for embedding generation"""
        components = []
        
        # Subject (weighted more heavily)
        subject = email_data.get('subject', '').strip()
        if subject and len(subject) > 2:
            components.append(f"Subject: {subject}")
            components.append(subject)  # Add twice for weighting
        
        # Sender
        sender = email_data.get('sender', '').strip()
        if sender and len(sender) > 2:
            components.append(f"From: {sender}")
        
        # Text content
        text_content = email_data.get('text_content', '').strip()
        if text_content and len(text_content) > 10:
            components.append(f"Content: {text_content[:1000]}")  # Limit content
        
        # Urgency words
        urgency_words = email_data.get('urgency_words', [])
        if urgency_words and isinstance(urgency_words, list):
            valid_words = [w.strip() for w in urgency_words if w and w.strip()]
            if valid_words:
                components.append(f"Urgency: {' '.join(valid_words)}")
        
        # URLs
        urls = email_data.get('urls', [])
        if urls and isinstance(urls, list):
            url_domains = []
            for url in urls[:5]:  # Limit URLs
                if url and isinstance(url, str) and '://' in url:
                    try:
                        domain = url.split('://')[1].split('/')[0].strip()
                        if domain and len(domain) > 3:
                            url_domains.append(domain)
                    except:
                        pass
            if url_domains:
                components.append(f"Domains: {' '.join(url_domains)}")
        
        # Create final text
        final_text = ' '.join(components).strip()
        
        # Ensure minimum content length
        if not final_text or len(final_text) < 10:
            # Use email ID as fallback
            email_id = email_data.get('id', 'unknown')
            final_text = f"Email ID: {email_id} - No extractable content"
        
        return final_text
    
    def ingest_emails(self, data_dir: str = "data") -> Dict[str, Any]:
        """Ingest emails into ChromaDB"""
        data_path = Path(data_dir)
        metadata_dir = data_path / "metadata"
        decoded_dir = data_path / "decoded_emails"
        
        if not metadata_dir.exists() or not decoded_dir.exists():
            raise ValueError(f"Required directories not found in {data_dir}")
        
        metadata_files = list(metadata_dir.glob("*.json"))
        print(f"📧 Found {len(metadata_files)} emails to process")
        
        # Check if collection already has data
        existing_count = self.collection.count()
        if existing_count > 0:
            print(f"⚠️  Collection already contains {existing_count} emails")
            response = input("Continue adding more emails? (y/n): ").lower()
            if response != 'y':
                return {"cancelled": True}
        
        stats = {
            "total_files": len(metadata_files),
            "processed": 0,
            "failed": 0,
            "embeddings_generated": 0
        }
        
        # Process in batches
        batch_size = 20  # Small batches for Voyage API
        batch_data = []
        batch_texts = []
        batch_ids = []
        
        for i, metadata_file in enumerate(metadata_files):
            decoded_file = decoded_dir / f"{metadata_file.stem}.txt"
            if not decoded_file.exists():
                stats["failed"] += 1
                continue
            
            # Extract email data
            email_data = self.extract_email_data(metadata_file, decoded_file)
            if not email_data:
                stats["failed"] += 1
                continue
            
            # Create embedding text
            embedding_text = self.create_embedding_text(email_data)
            
            batch_data.append(email_data)
            batch_texts.append(embedding_text)
            batch_ids.append(email_data['id'])
            
            # Process batch when full or at end
            if len(batch_data) >= batch_size or i == len(metadata_files) - 1:
                try:
                    print(f"🔄 Processing batch {len(batch_ids)} emails... ({stats['processed']}/{len(metadata_files)})")
                    
                    # Filter out empty texts before sending to API
                    valid_batch_data = []
                    valid_batch_texts = []
                    valid_batch_ids = []
                    
                    for data, text, id_val in zip(batch_data, batch_texts, batch_ids):
                        if text and text.strip() and len(text.strip()) >= 10:
                            valid_batch_data.append(data)
                            valid_batch_texts.append(text.strip())
                            valid_batch_ids.append(id_val)
                        else:
                            print(f"⚠️  Skipping {id_val} - insufficient content")
                            stats["failed"] += 1
                    
                    if not valid_batch_texts:
                        print("❌ No valid texts in batch, skipping...")
                        # Clear batch and continue
                        batch_data = []
                        batch_texts = []
                        batch_ids = []
                        continue
                    
                    print(f"📤 Sending {len(valid_batch_texts)} valid texts to Voyage API...")
                    
                    # Generate embeddings with Voyage
                    result = self.voyage_client.embed(
                        texts=valid_batch_texts,
                        model="voyage-3",
                        input_type="document"
                    )
                    
                    embeddings = result.embeddings
                    stats["embeddings_generated"] += len(embeddings)
                    
                    # Prepare metadata for ChromaDB using valid data only
                    metadatas = []
                    documents = []
                    
                    for email_data, embedding_text in zip(valid_batch_data, valid_batch_texts):
                        # Create metadata (ChromaDB has limitations on nested objects)
                        metadata = {
                            "subject": (email_data.get('subject', '') or '')[:200],  # Limit length
                            "sender": (email_data.get('sender', '') or '')[:100],
                            "date": (email_data.get('date', '') or '')[:50],
                            "url_count": len(email_data.get('urls', [])),
                            "urgency_count": len(email_data.get('urgency_words', [])),
                            "has_urls": len(email_data.get('urls', [])) > 0,
                            "has_urgency": len(email_data.get('urgency_words', [])) > 0,
                            "content_length": len(email_data.get('text_content', ''))
                        }
                        
                        metadatas.append(metadata)
                        documents.append(embedding_text[:1000])  # Limit document length
                    
                    # Add to ChromaDB
                    self.collection.add(
                        embeddings=embeddings,
                        documents=documents,
                        metadatas=metadatas,
                        ids=valid_batch_ids
                    )
                    
                    stats["processed"] += len(valid_batch_data)
                    
                    # Clear batch
                    batch_data = []
                    batch_texts = []
                    batch_ids = []
                    
                    # Small delay to respect API limits
                    time.sleep(1)
                    
                except Exception as e:
                    print(f"❌ Error processing batch: {e}")
                    stats["failed"] += len(batch_data)
                    
                    # Clear batch and continue
                    batch_data = []
                    batch_texts = []
                    batch_ids = []
        
        return stats
    
    def query_database(self, query: str, n_results: int = 10) -> Dict[str, Any]:
        """Query the ChromaDB database"""
        try:
            # Generate query embedding
            result = self.voyage_client.embed(
                texts=[query],
                model="voyage-3",
                input_type="query"
            )
            
            query_embedding = result.embeddings[0]
            
            # Search in ChromaDB
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
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            count = self.collection.count()
            return {
                "total_emails": count,
                "database_path": str(self.db_path),
                "collection_name": self.collection.name
            }
        except Exception as e:
            return {"error": str(e)}


def main():
    """Main setup function"""
    print("=" * 70)
    print("  Simple ChromaDB Setup with Voyage-3 Embeddings")
    print("=" * 70)
    
    try:
        # Initialize setup
        setup = SimpleChromaSetup()
        
        # Get current stats
        stats = setup.get_stats()
        if "error" not in stats:
            print(f"📊 Current database: {stats['total_emails']} emails")
        
        # Ask user what to do
        print("\nOptions:")
        print("1. 📥 Ingest emails into ChromaDB")
        print("2. 🔍 Query the database")
        print("3. 📊 Show database stats")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            print("\n🚀 Starting email ingestion...")
            result = setup.ingest_emails()
            
            if result.get("cancelled"):
                print("❌ Ingestion cancelled")
            else:
                print(f"\n✅ Ingestion complete!")
                print(f"   Processed: {result['processed']}")
                print(f"   Failed: {result['failed']}")
                print(f"   Embeddings generated: {result['embeddings_generated']}")
        
        elif choice == "2":
            query = input("Enter your search query: ").strip()
            if query:
                print(f"\n🔍 Searching for: '{query}'")
                results = setup.query_database(query, n_results=5)
                
                if "error" in results:
                    print(f"❌ Error: {results['error']}")
                else:
                    print(f"📊 Found {results['count']} results:")
                    
                    if results["count"] > 0:
                        for i, (id, metadata, distance) in enumerate(zip(
                            results["results"]["ids"][0],
                            results["results"]["metadatas"][0],
                            results["results"]["distances"][0]
                        ), 1):
                            similarity = 1 - distance
                            print(f"\n{i}. Email ID: {id}")
                            print(f"   Subject: {metadata.get('subject', 'N/A')[:60]}...")
                            print(f"   Sender: {metadata.get('sender', 'N/A')[:40]}...")
                            print(f"   Similarity: {similarity:.3f}")
                            print(f"   URLs: {metadata.get('url_count', 0)}")
                            print(f"   Urgency words: {metadata.get('urgency_count', 0)}")
        
        elif choice == "3":
            stats = setup.get_stats()
            print(f"\n📊 Database Statistics:")
            for key, value in stats.items():
                print(f"   {key}: {value}")
        
        else:
            print("❌ Invalid choice")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
