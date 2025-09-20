# Phishing Pot

![Phishing Pot](img/phishing_pot.png)

A collection of real phishing emails with tools to analyze and search them using AI.

## What's This?

This repository contains thousands of real phishing emails collected from honey pots, plus tools to:
- Decode and analyze phishing emails
- Find similar emails using AI
- Search by headers, content, or patterns
- Build vector databases for advanced similarity search

## Quick Start

### 1. Process Emails
```bash
python3 simple_batch_decoder.py
```
This converts raw email files into readable format with analysis.

### 2. Search Emails (3 ways)

**Simple keyword search:**
```bash
python3 simple_rag_retrieval.py
```

**Header-based search:**
```bash
python3 header_similarity_retrieval.py --interactive
```

**AI-powered similarity search:**
```bash
# First setup (requires Voyage API key in .env file)
python3 simple_chroma_setup.py

# Then search
python3 query_chroma_db.py --query "urgent account verification"
```

## Requirements

```bash
pip install -r requirements.txt
```

For AI search, get a free API key from [Voyage AI](https://www.voyageai.com/) and add it to `.env`:
```
VOYAGE_API_KEY=your_key_here
```

## File Structure

- `email/` - Raw phishing email files (.eml format)
- `data/` - Processed emails and metadata (created after running decoder)
- `simple_batch_decoder.py` - Main processing script
- `simple_rag_retrieval.py` - Basic search
- `header_similarity_retrieval.py` - Header-based search  
- `simple_chroma_setup.py` - AI database setup
- `query_chroma_db.py` - AI-powered search

## Use Cases

- **Security Research**: Analyze phishing patterns and techniques
- **Detection Development**: Train and test anti-phishing systems
- **Threat Intelligence**: Identify campaign similarities and trends
- **Education**: Study real-world phishing examples

## Contributing

Send phishing samples in .eml format. Replace sensitive info with `phishing@pot`:

```bash
sed -i 's/your@email.com/phishing@pot/' *.eml
```

## License

See [LICENSE](LICENSE) file.

---

**Note**: This is for research and detection purposes only. Not for creating phishing campaigns.