#!/usr/bin/env python3
# filepath: /home/nima/paper/final/he/tests.py

import subprocess
import time
import csv
import os
import sys
from loguru import logger

# Configure loguru to append to a text file
logger.configure(handlers=[
    {"sink": sys.stdout, "format": "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{message}</level>"},
    {"sink": "test_results.txt", "format": "{time:YYYY-MM-DD HH:mm:ss.SSS} | {message}", "rotation": "10 MB", "mode": "a"}
])


def run_command(command, verbose=True):
    """Run a shell command and return output"""
    if verbose:
        print(f"Running: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if verbose and result.stdout:
        print(result.stdout)
    if result.returncode != 0:
        print(f"Error running command: {command}")
        print(result.stderr)
        sys.exit(1)
    return result.stdout

def start_docker_services():
    """Start all Docker services"""
    print("Starting Docker services...")
    run_command("docker compose up --build -d")
    print("Docker services started successfully")

def clean_test_environment():
    """Clean the test environment"""
    print("\nCleaning test environment...")
    run_command("""
        clear && \\
        docker exec fhe-enc sh -c "rm -rf /bdt/build/results/* /bdt/build/private_data/* /bdt/build/cryptocontext/*" && \\
        docker exec fhe-main sh -c "rm -rf /bdt/build/results/*" && \\
        echo "Cleaning volumes done!" && \\
        echo "============ Results ===============" && \\
        docker exec fhe-enc ls /bdt/build/results/ /bdt/build/private_data/ /bdt/build/cryptocontext/ || true && \\
        echo "============================="
    """)

def run_encryption(security, depth, modulus):
    """Run encryption with specified parameters and return execution time"""
    print("\nRunning FHE encryption...")
    print("=============================")
    
    start_time = time.time()
    run_command(f"docker exec fhe-enc ./fhe-enc --security {security} --depth {depth} --modulus {modulus}")
    end_time = time.time()
    
    execution_time = end_time - start_time
    print(f"Encryption completed in {execution_time:.2f} seconds")
    return execution_time

def run_main_computation():
    """Run main computation and return execution time"""
    print("\nRunning FHE main...")
    print("=============================")
    
    start_time = time.time()
    run_command("docker exec fhe-main ./fhe-main")
    end_time = time.time()
    
    execution_time = end_time - start_time
    print(f"Main computation completed in {execution_time:.2f} seconds")
    return execution_time

def run_decryption():
    """Run decryption and return execution time"""
    print("\nRunning FHE decryption...")
    print("=============================")
    
    start_time = time.time()
    result = run_command("docker exec fhe-dec ./fhe-dec")
    end_time = time.time()
    
    execution_time = end_time - start_time
    print(f"Decryption completed in {execution_time:.2f} seconds")
    return execution_time, result

def run_tests():
    """Run all tests from the CSV file"""
    # Check if tests.csv exists
    if not os.path.exists('tests.csv'):
        print("Error: tests.csv file not found")
        sys.exit(1)
    
    # Read the tests.csv file
    tests = []
    with open('tests.csv', 'r') as f:
        reader = csv.reader(f)
        print(reader)
        header = next(reader)  # Skip the header
        for row in reader:
            # Parse row data
            test_data = {
                'test_no': int(row[0]),
                'depth': int(row[1]),
                'security': int(row[2]),
                'modulus': int(row[3].split(',')[0]),  # Split by comma and take first part
                'enc': 0,
                'main': 0,
                'dec': 0
            }
            tests.append(test_data)
    
    # Start Docker services once
    start_docker_services()
    
    # Run each test
    for test in tests:
        print(f"\n\n======= Running Test #{test['test_no']} =======")
        print(f"Parameters: depth={test['depth']}, security={test['security']}, modulus={test['modulus']}")
        
        # Clean test environment
        clean_test_environment()
        
        # Run encryption, main computation, and decryption
        test['enc'] = run_encryption(test['security'], test['depth'], test['modulus'])
        test['main'] = run_main_computation()
        test['dec'], dec_results = run_decryption()
        
        # Print test results
        result = dec_results.strip()
        test_config = f"Test #{test['test_no']} - Depth: {test['depth']}, Security: {test['security']}, Modulus: {test['modulus']}"
        result_header = f"\n--- Test #{test['test_no']} Results ---"
        enc_time = f"Encryption time: {test['enc']:.2f} seconds"
        main_time = f"Main computation time: {test['main']:.2f} seconds"
        dec_time = f"Decryption time: {test['dec']:.2f} seconds"
        total_time = f"Total time: {test['enc'] + test['main'] + test['dec']:.2f} seconds"
        
        # Print to console
        print(result_header)
        print(enc_time)
        print(main_time)
        print(dec_time)
        print(total_time)

        # Log to file
        logger.info(test_config)
        logger.info(result_header)
        logger.info(enc_time)
        logger.info(main_time)
        logger.info(dec_time)
        logger.info(total_time)
        logger.info(result)
    
    # Write results back to CSV
    with open('tests_results.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['test_no', 'depth', 'security', 'modulus', 'enc', 'main', 'dec'])
        for test in tests:
            writer.writerow([
                test['test_no'],
                test['depth'], 
                test['security'],
                test['modulus'],
                f"{test['enc']:.2f}",
                f"{test['main']:.2f}",
                f"{test['dec']:.2f}"
            ])
    
    print("\nAll tests completed successfully!")
    print(f"Results saved to tests_results.csv")

if __name__ == "__main__":
    run_tests()