# Crypto Address Monitor

A Python-based tool that monitors and extracts cryptocurrency wallet addresses from official U.S. government forfeiture notifications. This tool automatically downloads PDF notifications, processes them for cryptocurrency wallet addresses, and stores the extracted information in a MongoDB database.

## Features

- 🔄 Automatic PDF download and monitoring
- 🔍 Advanced pattern matching for cryptocurrency wallet addresses
- 📊 Data loss reporting and capture rate statistics
- 🗄️ MongoDB integration for data storage
- 🔐 SHA-256 hash verification for document changes
- 📅 Timestamp tracking for all entries

## Prerequisites

Before running this script, make sure you have the following installed:

```bash
pip install PyPDF2
pip install pymongo
pip install requests
```

You'll also need:
- MongoDB server running locally on the default port (27017)
- Internet connection to access forfeiture.gov
- Python 3.x

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd crypto-address-seizure-monitor
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

3. Ensure MongoDB is running on your system:
```bash
mongod
```

## Usage

Simply run the script:

```bash
python main.py
```

The script will:
1. Download the latest forfeiture notification PDF
2. Check if it's been modified since the last run
3. Extract cryptocurrency addresses if the document is new
4. Store the results in MongoDB

## Database Structure

### Collections

The script uses two MongoDB collections:

1. `PDF_Hashes`:
   - Stores document hashes and filenames
   - Used for change detection

2. `DataInfo3`:
   - Stores extracted cryptocurrency addresses
   - Contains detailed metadata about each address

### Data Schema

Each address entry contains:
```json
{
    "currency": "string",
    "address": "string",
    "tag": "sanctioned",
    "source": "USAO Official",
    "timestamp": integer,
    "confidence": "100",
    "info": ["string"],
    "mal": true
}
```

## Features in Detail

### PDF Processing
- Downloads PDFs from forfeiture.gov
- Generates unique filenames with timestamps
- Calculates SHA-256 hashes for change detection

### Pattern Matching
The script uses multiple regex patterns to capture different formats:
- Pattern 1: Matches detailed forfeiture entries with units and dates
- Pattern 2: Matches simplified address entries with currency
- Pattern 3: Catches standalone wallet addresses

### Error Handling
- Handles PDF download failures
- Reports data capture rates
- Manages file cleanup after processing

## Performance

The script provides real-time statistics on:
- Data capture rate
- Data loss percentage
- Processing success/failure

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
