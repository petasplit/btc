import os
import sys
import time
import hashlib
import binascii
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import base58
import ecdsa
import requests
import logging
import random

# Configure logging
logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

# Define a list of blockchain explorers or APIs to use for balance checking
blockchain_explorers = [
    "https://api.blockcypher.com/v1/btc/main/addrs/",
    "https://api.smartbit.com.au/v1/blockchain/address/",
    "https://blockchair.com/bitcoin/address/",
    "https://api.blockstream.com/address/",
    # Add more explorers/APIs here
]

def generate_private_key():
    """Generate a random private key."""
    return binascii.hexlify(os.urandom(32)).decode('utf-8')

def private_key_to_WIF(private_key):
    """Convert a private key to WIF format."""
    var80 = "80" + private_key
    var = hashlib.sha256(binascii.unhexlify(hashlib.sha256(binascii.unhexlify(var80)).hexdigest())).hexdigest()
    return str(base58.b58encode(binascii.unhexlify(var80 + var[:8])), 'utf-8')

def private_key_to_public_key(private_key):
    """Convert a private key to a public key."""
    sign = ecdsa.SigningKey.from_string(binascii.unhexlify(private_key), curve=ecdsa.SECP256k1)
    return '04' + binascii.hexlify(sign.verifying_key.to_string()).decode('utf-8')

def public_key_to_address(public_key):
    """Convert a public key to a Bitcoin address."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    var = hashlib.new('ripemd160')
    var.update(hashlib.sha256(binascii.unhexlify(public_key.encode())).digest())
    doublehash = hashlib.sha256(hashlib.sha256(binascii.unhexlify('00' + var.hexdigest().encode())).digest()).hexdigest()
    address = '00' + var.hexdigest() + doublehash[:8]
    count = len(address) - len(address.lstrip('0'))
    count //= 2
    n = int(address, 16)
    output = []
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    while len(output) < count:
        output.append(alphabet[0])
    return ''.join(output[::-1])

def check_balance(address):
    """Check the balance of a Bitcoin address using multiple blockchain explorers."""
    random.shuffle(blockchain_explorers)  # Shuffle the list of explorers to distribute requests
    for explorer in blockchain_explorers:
        url = f"{explorer}{address}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            if data.get("balance") is not None and data["balance"] > 0:
                return f"{data['balance']} BTC"
        except requests.exceptions.RequestException as e:
            logging.error(f"Error while checking balance for address {address} using {explorer}: {e}")
            continue
        except ValueError as e:
            logging.error(f"Error parsing JSON response from {explorer}: {e}")
            continue
    return None

def process_and_save(data):
    """Process data and save winning addresses to a file."""
    private_key, address, zi, wi = data
    balance = check_balance(address)
    if balance:
        if balance != '0 BTC':
            wi += 1
            with open("Winning.txt", "a", encoding="utf-8") as xf:
                xf.write(f"ADDRESS: {address}               BALANCE:{balance}\n"
                        f"PRIVATE KEY: {private_key}\n"
                        f"-----------------[ {time.thread_time()} ]------------------\n"
                        f"==================[ M M D R Z A . C o M ]==================\n")
            logging.info(f"Total: {zi * 8}, Win: {wi} - {address} : {private_key} : {balance}")
        else:
            logging.info(f"Total: {zi * 8}, Win: {wi} - {address} : {private_key} : {balance}")

def data_export(queue):
    """Generate and enqueue private keys, addresses, and counters."""
    zi = 0
    wi = 0
    while True:
        zi += 1
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)
        data = (private_key, address, zi, wi)
        queue.put(data)

def worker(queue):
    """Worker function to process data from the queue."""
    while True:
        data = queue.get()
        process_and_save(data)

def main():
    num_threads = multiprocessing.cpu_count()
    num_processes = num_threads // 2  # Use half of the available threads for processing
    data_queue = multiprocessing.Queue()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Start data generation
        executor.submit(data_export, data_queue)

        # Start worker processes
        for _ in range(num_processes):
            executor.submit(worker, data_queue)

if __name__ == '__main__':
    main()
