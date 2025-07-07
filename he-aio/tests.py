#!/usr/bin/env python3
# filepath: /home/nima/paper/final/he/tests.py

import subprocess
import time
import csv
import os
import sys
from loguru import logger
import functools

print = functools.partial(print, flush=True)

# Configure loguru to append to a text file
logger.configure(handlers=[
    {"sink": sys.stdout, "format": "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{message}</level>"},
    {"sink": "test_results.txt", "format": "{time:YYYY-MM-DD HH:mm:ss.SSS} | {message}", "rotation": "10 MB", "mode": "a"}
])


def run_command(cmd):
    commands = cmd.split(',')
    # Remove any whitespace
    commands = [command.strip() for command in commands]
    print('========================================')
    print (f'Running command: {cmd}')
    result = subprocess.run(commands, shell=True, stdout=subprocess.PIPE)
    stdout = result.stdout.decode('utf-8')
    print(f'=========== output of {cmd} ===========')
    print(stdout)
    print('========================================')
    return stdout


def run_command2(command, verbose=True):
    """Run a shell command and return output"""
    if verbose:
        print(f"Running: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if verbose and result.stdout:
        print(result.stdout)
    if result.returncode != 0:
        print(f"Error running command: {command}")
        print(result.stderr)
        raise Exception(f"Command failed with return code {result.returncode}: {result.stderr}")
    return result.stdout

def start_docker_services():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    """Start all Docker services"""
    print("Starting Docker services...")
    try:
        run_command("docker compose up --build -d")
        print("Docker services started successfully")
    except Exception as e:
        logger.error(f"Failed to start Docker services: {str(e)}")
        sys.exit(1)

def clean_test_environment():
    """Clean the test environment"""
    print("\nCleaning test environment...")
    try:
        run_command("""
            docker exec fhe-aio sh -c "rm -rf /bdt/build/data/* /bdt/build/results/* /bdt/build/private_data/* /bdt/build/cryptocontext/* /bdt/build/dec_results/*" && \\
            echo "Cleaning volumes done!" && \\
            echo "============ Results ===============" && \\
            docker exec fhe-aio ls /bdt/build/results/ /bdt/build/private_data/ /bdt/build/cryptocontext/ || true && \\
            echo "============================="
        """)
    except Exception as e:
        logger.error(f"Failed to clean test environment: {str(e)}")
        raise

def get_file_sizes():
    """Get the sizes of generated key and encrypted files"""
    try:
        output = run_command("docker exec fhe-aio ls -lh /bdt/build/data")

        # Initialize sizes
        sizes = {
            "public_size": "N/A",
            "eval_size": "N/A",
            "enc1_size": "N/A", 
            "enc2_size": "N/A"
        }
        
        # Parse output to get file sizes
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 5:  # Ensure line has enough parts
                size = parts[4]  # Size is typically in the 5th column
                filename = parts[-1]  # Filename is the last part
                
                if "key-public.txt" in filename:
                    sizes["public_size"] = size
                elif "key-eval-mult.txt" in filename:
                    sizes["eval_size"] = size
                elif "enc_file1.txt" in filename:
                    sizes["enc1_size"] = size
                elif "enc_file2.txt" in filename:
                    sizes["enc2_size"] = size
        
        logger.info(f"File sizes: Public key: {sizes['public_size']}, Eval key: {sizes['eval_size']}, " +
                    f"Enc file 1: {sizes['enc1_size']}, Enc file 2: {sizes['enc2_size']}")
                    
        return sizes
    except Exception as e:
        logger.error(f"Failed to get file sizes: {str(e)}")
        return {
            "public_size": "err",
            "eval_size": "err", 
            "enc1_size": "err",
            "enc2_size": "err"
        }

def run_encryption(security, depth, modulus):
    """Run encryption with specified parameters and return execution time"""
    print("\nRunning FHE encryption...")
    print("=============================")
    
    start_time = time.time()
    run_command(f"docker exec fhe-aio ./fhe-enc --security {security} --depth {depth} --modulus {modulus}")
    end_time = time.time()
    
    execution_time = end_time - start_time
    print(f"Encryption completed in {execution_time:.10f} seconds")
    return execution_time

def run_main_computation():
    """Run main computation and return execution time"""
    print("\nRunning FHE main...")
    print("=============================")
    
    start_time = time.time()
    run_command("docker exec fhe-aio ./fhe-main")
    end_time = time.time()
    
    execution_time = end_time - start_time
    print(f"Main computation completed in {execution_time:.10f} seconds")
    return execution_time

def run_decryption():
    """Run decryption and return execution time"""
    print("\nRunning FHE decryption...")
    print("=============================")
    
    start_time = time.time()
    result = run_command("docker exec fhe-aio ./fhe-dec")
    end_time = time.time()
    
    execution_time = end_time - start_time
    print(f"Decryption completed in {execution_time:.10f} seconds")
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
                'enc': "err",  # Default to error in case test fails
                'main': "err",
                'dec': "err",
                'public_size': "err",
                'eval_size': "err", 
                'enc1_size': "err",
                'enc2_size': "err"
            }
            tests.append(test_data)
    
    # Start Docker services once
    start_docker_services()
    
    # Run each test configuration
    for test in tests:
        print(f"\n\n======= Running Test #{test['test_no']} =======")
        print(f"Parameters: depth={test['depth']}, security={test['security']}, modulus={test['modulus']}")
        logger.info(f"Starting Test #{test['test_no']} - Depth: {test['depth']}, Security: {test['security']}, Modulus: {test['modulus']}")
        
        try:
            # Initialize timing accumulators
            enc_times = []
            main_times = []
            dec_times = []
            all_results = []
            file_sizes_data = []
            
            # Run the test 4 times
            for run in range(4):
                print(f"\n--- Run #{run+1} of 4 ---")
                logger.info(f"Run #{run+1} of 4 for Test #{test['test_no']}")
                
                try:
                    # Clean test environment
                    clean_test_environment()
                    
                    # Run encryption
                    enc_time = run_encryption(test['security'], test['depth'], test['modulus'])
                    enc_times.append(enc_time)
                    
                    # Get file sizes after encryption (only for the first run - sizes should be the same across runs)
                    if run == 0:
                        file_sizes = get_file_sizes()
                        test['public_size'] = file_sizes['public_size']
                        test['eval_size'] = file_sizes['eval_size']
                        test['enc1_size'] = file_sizes['enc1_size']
                        test['enc2_size'] = file_sizes['enc2_size']
                        
                    # Run main computation
                    main_time = run_main_computation()
                    main_times.append(main_time)
                    
                    # Run decryption
                    dec_time, dec_results = run_decryption()
                    dec_times.append(dec_time)
                    all_results.append(dec_results.strip())
                    
                    # Log individual run results
                    logger.info(f"Run #{run+1} - Encryption: {enc_time:.10f}s, Main: {main_time:.10f}s, Decryption: {dec_time:.10f}s")
                    
                except Exception as e:
                    logger.error(f"Run #{run+1} failed: {str(e)}")
                    print(f"Error in run #{run+1}: {str(e)}")
                    # If any run fails, we'll continue to the next run but mark the current one as failed
                    continue
                time.sleep(5)
            # Calculate averages if we have successful runs
            if enc_times:
                test['enc'] = sum(enc_times) / len(enc_times)
            if main_times:
                test['main'] = sum(main_times) / len(main_times)
            if dec_times:
                test['dec'] = sum(dec_times) / len(dec_times)
            
            # Print test results if all phases completed successfully
            if test['enc'] != "err" and test['main'] != "err" and test['dec'] != "err":
                test_config = f"Test #{test['test_no']} - Depth: {test['depth']}, Security: {test['security']}, Modulus: {test['modulus']}"
                result_header = f"\n--- Test #{test['test_no']} Average Results ({len(enc_times)} runs) ---"
                enc_time = f"Avg Encryption time: {test['enc']:.10f} seconds"
                main_time = f"Avg Main computation time: {test['main']:.10f} seconds"
                dec_time = f"Avg Decryption time: {test['dec']:.10f} seconds"
                total_time = f"Avg Total time: {test['enc'] + test['main'] + test['dec']:.10f} seconds"
                file_sizes_info = f"File sizes: Public key: {test['public_size']}, Eval key: {test['eval_size']}, " + \
                                 f"Enc file 1: {test['enc1_size']}, Enc file 2: {test['enc2_size']}"
                
                # Print to console
                print(result_header)
                print(enc_time)
                print(main_time)
                print(dec_time)
                print(total_time)
                print(file_sizes_info)
                
                # Log to file
                logger.info(result_header)
                logger.info(test_config)
                logger.info(enc_time)
                logger.info(main_time)
                logger.info(dec_time)
                logger.info(total_time)
                logger.info(file_sizes_info)
                if all_results:
                    logger.info(f"Last run result: {all_results[-1]}")
            else:
                # Log failure
                logger.error(f"Test #{test['test_no']} failed to complete all phases successfully")
                print(f"Test #{test['test_no']} failed")
                
        except Exception as e:
            # If any part fails, log the error but continue to the next test
            logger.error(f"Test #{test['test_no']} failed with error: {str(e)}")
            print(f"Error in test #{test['test_no']}: {str(e)}")
            # test values remain as "err" since they were initialized that way
        time.sleep(10)  # Wait a bit before next test to avoid resource contention
    # Write results back to CSV
    with open('tests_results.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['test_no', 'depth', 'security', 'modulus', 'enc', 'main', 'dec', 
                         'public_size', 'eval_size', 'enc1_size', 'enc2_size'])
        for test in tests:
            # Format numeric values with high precision or keep "err" string
            enc_value = f"{test['enc']:.10f}" if isinstance(test['enc'], float) else test['enc']
            main_value = f"{test['main']:.10f}" if isinstance(test['main'], float) else test['main']
            dec_value = f"{test['dec']:.10f}" if isinstance(test['dec'], float) else test['dec']
            
            writer.writerow([
                test['test_no'],
                test['depth'], 
                test['security'],
                test['modulus'],
                enc_value,
                main_value,
                dec_value,
                test['public_size'],
                test['eval_size'],
                test['enc1_size'],
                test['enc2_size']
            ])
    
    print("\nAll tests completed!")
    print(f"Results saved to tests_results.csv")

if __name__ == "__main__":
    run_tests()