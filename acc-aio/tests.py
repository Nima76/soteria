#!/usr/bin/env python3
# filepath: /home/nima/paper/final/he/tests.py

import subprocess
import time
import csv
import os
import sys
import pandas as pd
from loguru import logger
import functools

print = functools.partial(print, flush=True)

# Configure loguru to append to a text file
logger.configure(handlers=[
    {"sink": sys.stdout, "format": "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{message}</level>"},
    {"sink": "test_results.txt", "format": "{time:YYYY-MM-DD HH:mm:ss.SSS} | {message}", "rotation": "10 MB", "mode": "a"}
])


def run_command(cmd, printer=True):
    commands = cmd.split(',')
    # Remove any whitespace
    commands = [command.strip() for command in commands]
    if printer:
        print('========================================')
        print (f'Running command: {cmd}')
    else:
        print('========================================')
        print(f'Running a command')
    result = subprocess.run(commands, shell=True, stdout=subprocess.PIPE)
    stdout = result.stdout.decode('utf-8')
    print(f'{"#"*20} output of {cmd} {"#"*20}')
    print(stdout)
    print('========================================')
    return stdout

def start_docker_services():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    """Start all Docker services"""
    print("Starting Docker services...")
    try:
        run_command("sudo docker compose up --build -d")
        # print("Docker services started successfully")
    except Exception as e:
        logger.error(f"Failed to start Docker services: {str(e)}")
        sys.exit(1)

def clean_test_environment():
    """Clean the test environment"""
    print("\nCleaning test environment...")
    try:
        run_command("""
            sudo docker exec acc-aio sh -c "rm -rf /bdt/build/data/* /bdt/build/results/* /bdt/build/private_data/* /bdt/build/cryptocontext/* /bdt/build/dec_results/*" && \\
            echo "Cleaning volumes done!" && \\
            echo "============ Results ===============" && \\
            sudo docker exec acc-aio ls /bdt/build/results/ /bdt/build/private_data/ /bdt/build/cryptocontext/ || true && \\
            echo "============================="
        """, printer=False)
    except Exception as e:
        logger.error(f"Failed to clean test environment: {str(e)}")
        raise

def get_file_sizes():
    """Get the sizes of generated key and encrypted files in bytes"""
    try:
        output = run_command("sudo docker exec acc-aio ls -la /bdt/build/data")

        # Initialize sizes
        sizes = {
            "public_size": 0,
            "eval_size": 0,
            "enc1_size": 0, 
            "enc2_size": 0
        }
        
        # Parse output to get file sizes
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 5:  # Ensure line has enough parts
                try:
                    size_bytes = int(parts[4])  # Size in bytes (5th column)
                    filename = parts[-1]  # Filename is the last part
                    
                    if "key-public.txt" in filename:
                        sizes["public_size"] = size_bytes
                    elif "key-eval-mult.txt" in filename:
                        sizes["eval_size"] = size_bytes
                    elif "enc_file1.txt" in filename:
                        sizes["enc1_size"] = size_bytes
                    elif "enc_file2.txt" in filename:
                        sizes["enc2_size"] = size_bytes
                except ValueError:
                    # Skip lines where size is not a number (like directory entries)
                    continue
        
        logger.info(f"File sizes: Public key: {sizes['public_size']} bytes, Eval key: {sizes['eval_size']} bytes, " +
                    f"Enc file 1: {sizes['enc1_size']} bytes, Enc file 2: {sizes['enc2_size']} bytes")
                    
        return sizes
    except Exception as e:
        logger.error(f"Failed to get file sizes: {str(e)}")
        return {
            "public_size": 0,
            "eval_size": 0, 
            "enc1_size": 0,
            "enc2_size": 0
        }

def run_encryption(security, depth, modulus):
    """Run encryption with specified parameters"""
    print("Running FHE encryption...")
    run_command(f"sudo docker exec acc-aio ./fhe-enc --security {security} --depth {depth} --modulus {modulus}")
    print("Encryption completed")

def run_main_computation_old():
    """Run main computation"""
    print("Running FHE main...")
    run_command("sudo docker exec acc-aio ./fhe-main")
    print("Main computation completed")

def run_main_computation(gpu_params=None):
    """Run main computation with optional GPU parameters"""
    print("Running FHE main...")
    print("=============================")
    cmd = "sudo docker exec acc-aio ./fhe-main"
    # If GPU parameters are provided, add them as command-line arguments
    if gpu_params:
        params_str = " ".join(str(param) for param in gpu_params)
        cmd = f"sudo docker exec acc-aio ./fhe-main {params_str}"
    run_command(cmd)
    print("Main computation completed")


def run_decryption():
    """Run decryption"""
    print("Running FHE decryption...")
    result = run_command("sudo docker exec acc-aio ./fhe-dec")
    print("Decryption completed")
    return result

def copy_csv_files_from_container():
    """Copy CSV timing files from container to host"""
    try:
        # Copy CSV files from container to host
        run_command("sudo docker cp acc-aio:/bdt/build/enc_timing_results.csv ./enc_timing_results.csv")
        run_command("sudo docker cp acc-aio:/bdt/build/main_timing_results.csv ./main_timing_results.csv") 
        run_command("sudo docker cp acc-aio:/bdt/build/dec_timing_results.csv ./dec_timing_results.csv")
        print("CSV files copied from container successfully")
    except Exception as e:
        logger.error(f"Failed to copy CSV files: {str(e)}")
        raise

def read_timing_data():
    """Read timing data from CSV files generated by C++ applications"""
    timing_data = {
        'enc': [],
        'main': [],
        'dec': []
    }
    
    try:
        # Read encryption timing data
        if os.path.exists('enc_timing_results.csv'):
            with open('enc_timing_results.csv', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    timing_data['enc'].append(row)
        
        # Read main computation timing data
        if os.path.exists('main_timing_results.csv'):
            with open('main_timing_results.csv', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    timing_data['main'].append(row)
        
        # Read decryption timing data
        if os.path.exists('dec_timing_results.csv'):
            with open('dec_timing_results.csv', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    timing_data['dec'].append(row)
                    
    except Exception as e:
        logger.error(f"Failed to read timing data: {str(e)}")
        
    return timing_data

def consolidate_timing_data():
    """Consolidate all timing data into a single comprehensive CSV file"""
    try:
        # Read all timing data
        timing_data = read_timing_data()
        
        # Create consolidated data structure
        consolidated_data = []
        
        # Process encryption data
        for row in timing_data['enc']:
            consolidated_row = {
                'timestamp': row['timestamp'],
                'phase': row['phase'],
                'depth': row['depth'],
                'modulus': row['modulus'],
                'security': row['security'],
                'enc_context_time': row.get('context_time', ''),
                'enc_keygen_time': row.get('keygen_time', ''),
                'enc_encrypt_time': row.get('encrypt_time', ''),
                'enc_serialize_time': row.get('serialize_time', ''),
                'enc_total_time': row.get('total_time', ''),
                'main_deserialize_time': '',
                'main_computation_time': '',
                'main_serialize_time': '',
                'main_total_time': '',
                'dec_deserialize_time': '',
                'dec_decrypt_time': '',
                'dec_save_time': '',
                'dec_total_time': ''
            }
            consolidated_data.append(consolidated_row)
        
        # Process main computation data
        for row in timing_data['main']:
            consolidated_row = {
                'timestamp': row['timestamp'],
                'phase': row['phase'],
                'depth': row['depth'],
                'modulus': row['modulus'],
                'security': row['security'],
                'enc_context_time': '',
                'enc_keygen_time': '',
                'enc_encrypt_time': '',
                'enc_serialize_time': '',
                'enc_total_time': '',
                'main_deserialize_time': row.get('deserialize_time', ''),
                'main_computation_time': row.get('computation_time', ''),
                'main_serialize_time': row.get('serialize_time', ''),
                'main_total_time': row.get('total_time', ''),
                'dec_deserialize_time': '',
                'dec_decrypt_time': '',
                'dec_save_time': '',
                'dec_total_time': ''
            }
            consolidated_data.append(consolidated_row)
        
        # Process decryption data
        for row in timing_data['dec']:
            consolidated_row = {
                'timestamp': row['timestamp'],
                'phase': row['phase'],
                'depth': row['depth'],
                'modulus': row['modulus'],
                'security': row['security'],
                'enc_context_time': '',
                'enc_keygen_time': '',
                'enc_encrypt_time': '',
                'enc_serialize_time': '',
                'enc_total_time': '',
                'main_deserialize_time': '',
                'main_computation_time': '',
                'main_serialize_time': '',
                'main_total_time': '',
                'dec_deserialize_time': row.get('deserialize_time', ''),
                'dec_decrypt_time': row.get('decrypt_time', ''),
                'dec_save_time': row.get('save_time', ''),
                'dec_total_time': row.get('total_time', '')
            }
            consolidated_data.append(consolidated_row)
        
        # Write consolidated data to CSV
        if consolidated_data:
            with open('consolidated_timing_results.csv', 'w', newline='') as f:
                fieldnames = [
                    'timestamp', 'phase', 'depth', 'modulus', 'security',
                    'enc_context_time', 'enc_keygen_time', 'enc_encrypt_time', 'enc_serialize_time', 'enc_total_time',
                    'main_deserialize_time', 'main_computation_time', 'main_serialize_time', 'main_total_time',
                    'dec_deserialize_time', 'dec_decrypt_time', 'dec_save_time', 'dec_total_time'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(consolidated_data)
            
            print("Consolidated timing data saved to consolidated_timing_results.csv")
            logger.info("Consolidated timing data created successfully")
        else:
            print("No timing data found to consolidate")
            logger.warning("No timing data found to consolidate")
            
    except Exception as e:
        logger.error(f"Failed to consolidate timing data: {str(e)}")

def calculate_test_summary_with_sizes(tests):
    """Calculate summary statistics for each test configuration including file sizes"""
    try:
        timing_data = read_timing_data()
        
        # Group data by test configuration
        test_groups = {}
        
        for phase in ['enc', 'main', 'dec']:
            for row in timing_data[phase]:
                key = f"{row['depth']}_{row['modulus']}_{row['security']}"
                if key not in test_groups:
                    test_groups[key] = {
                        'depth': row['depth'],
                        'modulus': row['modulus'],
                        'security': row['security'],
                        'enc_times': [],
                        'main_times': [],
                        'dec_times': []
                    }
                
                if phase == 'enc':
                    test_groups[key]['enc_times'].append(float(row['total_time']))
                elif phase == 'main':
                    test_groups[key]['main_times'].append(float(row['total_time']))
                elif phase == 'dec':
                    test_groups[key]['dec_times'].append(float(row['total_time']))
        
        # Calculate averages and write summary with file sizes
        with open('test_summary.csv', 'w', newline='') as f:
            fieldnames = [
                'test_number', 'depth', 'modulus', 'security', 
                'avg_enc_time', 'avg_main_time', 'avg_dec_time', 'avg_total_time',
                'public_key_size_bytes', 'eval_key_size_bytes', 'enc1_size_bytes', 'enc2_size_bytes'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for test in tests:
                if test['status'] == 'completed':
                    key = f"{test['depth']}_{test['modulus']}_{test['security']}"
                    if key in test_groups:
                        data = test_groups[key]
                        avg_enc = sum(data['enc_times']) / len(data['enc_times']) if data['enc_times'] else 0
                        avg_main = sum(data['main_times']) / len(data['main_times']) if data['main_times'] else 0
                        avg_dec = sum(data['dec_times']) / len(data['dec_times']) if data['dec_times'] else 0
                        avg_total = avg_enc + avg_main + avg_dec
                        
                        # Get file sizes for this test
                        file_sizes = test.get('file_sizes', {})
                        
                        writer.writerow({
                            'test_number': test['test_no'],
                            'depth': test['depth'],
                            'modulus': test['modulus'],
                            'security': test['security'],
                            'avg_enc_time': f"{avg_enc:.10f}",
                            'avg_main_time': f"{avg_main:.10f}",
                            'avg_dec_time': f"{avg_dec:.10f}",
                            'avg_total_time': f"{avg_total:.10f}",
                            'public_key_size_bytes': file_sizes.get('public_size', 0),
                            'eval_key_size_bytes': file_sizes.get('eval_size', 0),
                            'enc1_size_bytes': file_sizes.get('enc1_size', 0),
                            'enc2_size_bytes': file_sizes.get('enc2_size', 0)
                        })
        
        print("Test summary with file sizes saved to test_summary.csv")
        logger.info("Test summary with file sizes created successfully")
        
    except Exception as e:
        logger.error(f"Failed to calculate test summary with file sizes: {str(e)}")

def calculate_test_summary():
    """Legacy function - redirects to new function with file sizes"""
    logger.warning("Using legacy calculate_test_summary - file sizes will not be included")
    return calculate_test_summary_with_sizes([])


def format_file_size(size_bytes):
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"

def create_human_readable_summary(tests):
    """Create an additional summary with human-readable file sizes"""
    try:
        with open('test_summary_readable.csv', 'w', newline='') as f:
            fieldnames = [
                'test_number', 'depth', 'modulus', 'security',
                'public_key_size', 'eval_key_size', 'enc1_size', 'enc2_size'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for test in tests:
                if test['status'] == 'completed' and 'file_sizes' in test:
                    file_sizes = test['file_sizes']
                    writer.writerow({
                        'test_number': test['test_no'],
                        'depth': test['depth'],
                        'modulus': test['modulus'],
                        'security': test['security'],
                        'public_key_size': format_file_size(file_sizes.get('public_size', 0)),
                        'eval_key_size': format_file_size(file_sizes.get('eval_size', 0)),
                        'enc1_size': format_file_size(file_sizes.get('enc1_size', 0)),
                        'enc2_size': format_file_size(file_sizes.get('enc2_size', 0))
                    })
        
        print("Human-readable file sizes saved to test_summary_readable.csv")
        
    except Exception as e:
        logger.error(f"Failed to create human-readable summary: {str(e)}")

def load_gpu_parameters():
    """Load GPU parameters from Book3.csv"""
    gpu_params_map = {}
    
    try:
        if os.path.exists('tests.csv'):
            with open('tests.csv', 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Create a key from depth, modulus, security
                    key = f"{row['depth']}_{row['modulus']}_{row['security']}"
                    
                    # Store GPU parameters
                    gpu_params_map[key] = {
                        'gpu_blocks': int(row['gpu blocks']),
                        'gpu_threads': int(row['gpu threads']),
                        'streams': int(row['streams']),
                        'ringDim': int(row['ringDim']),
                        'sizeP': int(row['sizeP']),
                        'sizeQ': int(row['sizeQ']),
                        'paramSizeY': int(row['paramSizeY'])
                    }
            
            logger.info(f"Loaded GPU parameters for {len(gpu_params_map)} configurations from Book3.csv")
            
        else:
            logger.warning("tests.csv file not found. Using default GPU parameters.")
    
    except Exception as e:
        logger.error(f"Failed to load GPU parameters: {str(e)}")
    
    return gpu_params_map

def run_tests():
    """Run all tests from the CSV file"""
    # Check if tests.csv exists
    if not os.path.exists('tests.csv'):
        print("Error: tests.csv file not found")
        sys.exit(1)
    
    # Read the tests.csv file
    gpu_params_map = load_gpu_parameters()
    tests = []
    with open('tests.csv', 'r') as f:
        reader = csv.reader(f)
        # print(reader)
        header = next(reader)  # Skip the header
        for row in reader:
            # Parse row data
            test_data = {
                'test_no': int(row[0]),
                'depth': int(row[1]),
                'security': int(row[2]),
                'modulus': int(row[3].split(',')[0]),  # Split by comma and take first part
                'status': 'pending',
                'file_sizes': {}  # Add file sizes storage
            }
            tests.append(test_data)
    
    # Start Docker services once
    start_docker_services()
    
    # Run each test configuration
    for test in tests:
        print(f"\n\n======= Running Test #{test['test_no']} =======")
        print(f"Parameters: depth={test['depth']}, security={test['security']}, modulus={test['modulus']}")
        logger.info(f"Starting Test #{test['test_no']} - Depth: {test['depth']}, Security: {test['security']}, Modulus: {test['modulus']}")
        key = f"{test['depth']}_{test['modulus']}_{test['security']}"
        
        gpu_params = None
        if key in gpu_params_map:
            params = gpu_params_map[key]
            gpu_params = [
                params['gpu_blocks'],
                params['gpu_threads'],
                params['streams'],
                params['ringDim'],
                params['sizeP'],
                params['sizeQ'],
                params['paramSizeY']
            ]
            print(f"Found GPU parameters for configuration {key}: {gpu_params}")
            logger.info(f"Using GPU parameters for Test #{test['test_no']}: {gpu_params}")
        else:
            logger.warning(f"No GPU parameters found for configuration {key}. Using default.")
        
        try:
            # Run the test 4 times
            for run in range(4):
                print(f"\n--- Run #{run+1} of 4 ---")
                logger.info(f"Run #{run+1} of 4 for Test #{test['test_no']}")
                
                try:
                    # Clean test environment
                    clean_test_environment()
                    
                    # Run encryption
                    run_encryption(test['security'], test['depth'], test['modulus'])
                    
                    # Get file sizes after encryption (only for the first run)
                    if run == 0:
                        file_sizes = get_file_sizes()
                        test['file_sizes'] = file_sizes  # Store file sizes for this test
                        logger.info(f"File sizes for Test #{test['test_no']}: {file_sizes}")
                        
                    # Run main computation
                    run_main_computation(gpu_params)
                    
                    # Run decryption
                    dec_results = run_decryption()
                    
                    # Log individual run completion
                    logger.info(f"Run #{run+1} completed successfully")
                    
                except Exception as e:
                    logger.error(f"Run #{run+1} failed: {str(e)}")
                    print(f"Error in run #{run+1}: {str(e)}")
                    continue
                    
                time.sleep(5)  # Wait between runs
            
            test['status'] = 'completed'
            logger.info(f"Test #{test['test_no']} completed successfully")
                
        except Exception as e:
            # If any part fails, log the error but continue to the next test
            logger.error(f"Test #{test['test_no']} failed with error: {str(e)}")
            print(f"Error in test #{test['test_no']}: {str(e)}")
            test['status'] = 'failed'
            
        time.sleep(10)  # Wait between tests
    
    # Copy CSV files from container after all tests
    print("\nCopying timing CSV files from container...")
    copy_csv_files_from_container()
    
    # Consolidate timing data
    print("\nConsolidating timing data...")
    consolidate_timing_data()
    
    # Calculate test summary with file sizes
    print("\nCalculating test summary...")
    calculate_test_summary_with_sizes(tests)

    # Optional: Create human-readable summary
    print("\nCreating human-readable file size summary...")
    create_human_readable_summary(tests)
    
    print("\nAll tests completed!")
    print("Generated files:")
    print("- consolidated_timing_results.csv: Detailed timing data from all phases")
    print("- test_summary.csv: Summary statistics for each test configuration with file sizes")
    print("- enc_timing_results.csv: Encryption timing data")
    print("- main_timing_results.csv: Main computation timing data")
    print("- dec_timing_results.csv: Decryption timing data")

if __name__ == "__main__":
    run_tests()
