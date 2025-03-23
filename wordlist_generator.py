#!/usr/bin/env python3
"""
WiFi Wordlist Generator - Creates custom wordlists for password cracking.
Allows user to specify character sets, length ranges, and special patterns.
"""

import os
import sys
import argparse
import string
import itertools
import logging
import time
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("wordlist_generator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("wordlist_generator")

class WordlistGenerator:
    def __init__(self):
        """Initialize the WordlistGenerator with character sets."""
        self.charsets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': string.punctuation,
            'all': string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        }
        
        # Common password patterns
        self.patterns = {
            'years': [str(year) for year in range(1990, 2030)],
            'common_suffixes': ['123', '1234', '12345', '123456', '!', '#', '@', '$']
        }

    def generate_fixed_length(self, charset, length, output_file, batch_size=1000000):
        """Generate all possible combinations of fixed length."""
        logger.info(f"Generating fixed length passwords (length={length})")
        count = 0
        
        # Calculate total combinations for progress bar
        total = len(charset) ** length
        if total > 1000000000:  # If more than a billion combinations
            logger.warning(f"Generating {total} combinations. This may take a very long time and create a large file.")
            confirm = input("Continue? (y/n): ")
            if confirm.lower() != 'y':
                return 0
        
        with open(output_file, 'a') as f:
            # Use itertools.product to generate all combinations
            batch = []
            for combo in tqdm(itertools.product(charset, repeat=length), total=total):
                password = ''.join(combo)
                batch.append(password)
                count += 1
                
                # Write in batches to improve performance
                if len(batch) >= batch_size:
                    f.write('\n'.join(batch) + '\n')
                    batch = []
            
            # Write any remaining passwords
            if batch:
                f.write('\n'.join(batch) + '\n')
                
        return count

    def generate_range_length(self, charset, min_length, max_length, output_file):
        """Generate passwords with lengths in the specified range."""
        total_count = 0
        for length in range(min_length, max_length + 1):
            count = self.generate_fixed_length(charset, length, output_file)
            total_count += count
        return total_count

    def generate_with_common_patterns(self, base_words, output_file):
        """Generate passwords using common patterns with base words."""
        logger.info("Generating passwords with common patterns")
        count = 0
        
        with open(output_file, 'a') as f:
            for word in tqdm(base_words):
                # Original word
                f.write(f"{word}\n")
                count += 1
                
                # Word with years
                for year in self.patterns['years']:
                    f.write(f"{word}{year}\n")
                    count += 1
                
                # Word with common suffixes
                for suffix in self.patterns['common_suffixes']:
                    f.write(f"{word}{suffix}\n")
                    count += 1
                    
                # Capitalize first letter
                cap_word = word.capitalize()
                if cap_word != word:
                    f.write(f"{cap_word}\n")
                    count += 1
                    
                    # Capitalized with years and suffixes
                    for year in self.patterns['years']:
                        f.write(f"{cap_word}{year}\n")
                        count += 1
                    
                    for suffix in self.patterns['common_suffixes']:
                        f.write(f"{cap_word}{suffix}\n")
                        count += 1
        
        return count

    def add_base_words(self, base_words_file, output_file):
        """Add custom base words from a file."""
        if not os.path.exists(base_words_file):
            logger.error(f"Base words file not found: {base_words_file}")
            return []
            
        base_words = []
        count = 0
        
        with open(base_words_file, 'r') as infile, open(output_file, 'a') as outfile:
            for line in infile:
                word = line.strip()
                if word:
                    base_words.append(word)
                    outfile.write(f"{word}\n")
                    count += 1
        
        logger.info(f"Added {count} base words from {base_words_file}")
        return base_words

    def generate_wordlist(self, output_file, min_length=8, max_length=10, 
                         use_lowercase=True, use_uppercase=False, use_digits=True, 
                         use_special=False, base_words_file=None, use_patterns=True):
        """Generate a complete wordlist based on specified parameters."""
        # Initialize charset based on parameters
        charset = ''
        if use_lowercase:
            charset += self.charsets['lowercase']
        if use_uppercase:
            charset += self.charsets['uppercase']
        if use_digits:
            charset += self.charsets['digits']
        if use_special:
            charset += self.charsets['special']
            
        if not charset:
            logger.error("No character sets selected. Please select at least one character set.")
            return
            
        logger.info(f"Generating wordlist to {output_file}")
        logger.info(f"Character set: {'lowercase ' if use_lowercase else ''}{'uppercase ' if use_uppercase else ''}{'digits ' if use_digits else ''}{'special' if use_special else ''}")
        logger.info(f"Length range: {min_length} to {max_length}")
        
        # Create new file or overwrite existing
        with open(output_file, 'w') as f:
            pass  # Just create/clear the file
            
        total_count = 0
        start_time = time.time()
        
        # Add base words if specified
        base_words = []
        if base_words_file:
            base_words = self.add_base_words(base_words_file, output_file)
            total_count += len(base_words)
            
        # Generate passwords with common patterns based on base words
        if base_words and use_patterns:
            pattern_count = self.generate_with_common_patterns(base_words, output_file)
            total_count += pattern_count
            logger.info(f"Generated {pattern_count} passwords with common patterns")
            
        # Generate passwords of specified length range
        range_count = self.generate_range_length(charset, min_length, max_length, output_file)
        total_count += range_count
        
        duration = time.time() - start_time
        logger.info(f"Wordlist generation complete. Generated {total_count} passwords in {duration:.2f} seconds.")
        logger.info(f"Wordlist saved to {output_file}")

def main():
    """Parse arguments and run the wordlist generator."""
    parser = argparse.ArgumentParser(description='WiFi Wordlist Generator')
    parser.add_argument('-o', '--output', default='/var/handshake_cracker/wordlist.txt',
                        help='Output wordlist file path')
    parser.add_argument('--min-length', type=int, default=8,
                        help='Minimum password length')
    parser.add_argument('--max-length', type=int, default=10,
                        help='Maximum password length')
    parser.add_argument('--lowercase', action='store_true', default=True,
                        help='Include lowercase letters')
    parser.add_argument('--uppercase', action='store_true',
                        help='Include uppercase letters')
    parser.add_argument('--digits', action='store_true', default=True,
                        help='Include digits')
    parser.add_argument('--special', action='store_true',
                        help='Include special characters')
    parser.add_argument('--no-lowercase', action='store_false', dest='lowercase',
                        help='Exclude lowercase letters')
    parser.add_argument('--no-digits', action='store_false', dest='digits',
                        help='Exclude digits')
    parser.add_argument('--base-words', 
                        help='File containing base words to include')
    parser.add_argument('--no-patterns', action='store_false', dest='use_patterns',
                        help='Disable generation of common patterns with base words')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.min_length > args.max_length:
        logger.error("Minimum length cannot be greater than maximum length")
        sys.exit(1)
        
    if args.min_length < 3:
        logger.warning("Minimum length less than 3 may generate an extremely large wordlist")
        confirm = input("Continue? (y/n): ")
        if confirm.lower() != 'y':
            sys.exit(0)
    
    # Create output directory if it doesn't exist
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    
    # Generate wordlist
    generator = WordlistGenerator()
    generator.generate_wordlist(
        args.output,
        min_length=args.min_length,
        max_length=args.max_length,
        use_lowercase=args.lowercase,
        use_uppercase=args.uppercase,
        use_digits=args.digits,
        use_special=args.special,
        base_words_file=args.base_words,
        use_patterns=args.use_patterns
    )

if __name__ == "__main__":
    main()
