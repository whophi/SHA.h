import subprocess

formats_per_test = ['ShortMsg', 'LongMsg']
sha_sizes_1_2 = ['1', '224', '256', '384', '512', '512_224', '512_256']
sha_sizes_3 = ['3_224', '3_256', '3_384', '3_512']
sha_sizes_3 = ['3_224', '3_256', '3_384', '3_512']
shake_sizes = ['128', '256']

PRINT_SUCCESS: bool = False


def sha_test_dir(exe: str, dir: str, prepend: str, sizes, is_shake: bool = False):
  for alg in sizes:
    for format in formats_per_test:
      file = open(dir + prepend + alg + format + '.rsp')
      while True:
        line = 't'
        while(line != '' and not line.startswith('Len')): line = file.readline()
        if(line == ''): break

        len: int = int(line.split(' = ')[1])
        msg: str = file.readline().split(' = ')[1].strip()
        md: str = file.readline().split(' = ')[1].strip()

        # Windows only?
        if len > 130464:
          print('Cannot pass messages larger then 130464bits over command line argument. Was {len} (skipping it)'.format(len=len))
          continue

        alg_str: str = ('shake_' if is_shake else '') + alg
        if PRINT_SUCCESS: print('Running: %s %s %d %s -- ' % (exe, alg_str, len, msg), end='')
        result = subprocess.run([exe, alg_str, str(len), msg], stdout=subprocess.PIPE)
        result_md = result.stdout.decode('utf-8').strip()
        if(result_md != md): 
          if not PRINT_SUCCESS:
            print('Running: %s %s %d %s -- ' % (exe, alg_str, len, msg), end='')
          print('Failed:', alg_str, format)
          print('\t len =', len)
          print('\t msg =', msg)
          print('\t expected md =', md)
          print('\t actual   md =', result_md)
          exit(1)
        elif PRINT_SUCCESS:
          print('Success:', alg_str, format)

def shake_test_vo_dir(exe: str, dir: str, sizes):
  for alg in sizes:
    for format in formats_per_test:
      file = open(dir + 'SHAKE' + alg + 'VariableOut' + '.rsp')
      msg_size: int = 0
      while True:
        line = 't'
        while line != '':
          if(line.startswith('Outputlen')): break
          elif(line.startswith('[Input Length =')): 
            msg_size = int(line.split(' = ')[1].replace(']', '').strip())
          line = file.readline()
        if(line == ''): break

        len: int = msg_size
        out_len: int = line.split(' = ')[1].strip()
        msg: str = file.readline().split(' = ')[1].strip()
        md: str = file.readline().split(' = ')[1].strip()

        alg_str: str = 'shake_' + alg
        if PRINT_SUCCESS: print('Running: %s %s %d %s %s -- ' % (exe, alg_str, len, msg, out_len), end='')
        result = subprocess.run([exe, alg_str, str(len), msg, out_len], stdout=subprocess.PIPE)
        result_md = result.stdout.decode('utf-8').strip()
        if(result_md != md):
          if not PRINT_SUCCESS:
            print('Running: %s %s %d %s %s -- ' % (exe, alg_str, len, msg, out_len), end='')
          print('Failed:', alg_str, format)
          print('\t len =', len)
          print('\t msg =', msg)
          print('\t out_len =', out_len)
          print('\t expected md =', md)
          print('\t actual   md =', result_md)
          exit(1)
        elif PRINT_SUCCESS:
          print('Success:', alg, format)


make_run = subprocess.run(['make', '-B'])
if make_run.returncode != 0:
  print("Failed to compile tests.")
  exit(1)
exes = ['./test.exe', './test_no_simd.exe']

for exe in exes:
  print("Testing:", exe)
  print("\tSHA1/2 ", end='', flush=True)
  sha_test_dir(exe, './data/nist/sha1_2_bits/', 'SHA', sha_sizes_1_2)
  sha_test_dir(exe, './data/nist/sha1_2_bytes/', 'SHA', sha_sizes_1_2)
  print('-- Success')
  print("\tTesting SHA3 ", end='', flush=True)
  sha_test_dir(exe, './data/nist/sha3_bits/', 'SHA', sha_sizes_3)
  sha_test_dir(exe, './data/nist/sha3_bytes/', 'SHA', sha_sizes_3)
  print('-- Success')
  print("\tTesting Shake msg size ", end='', flush=True)
  sha_test_dir(exe, './data/nist/shake_bits/', 'SHAKE', shake_sizes, True)
  sha_test_dir(exe, './data/nist/shake_bytes/', 'SHAKE', shake_sizes, True)
  print('-- Success')
  print("\tTesting Shake out size ", end='', flush=True)
  shake_test_vo_dir(exe, './data/nist/shake_bits/', shake_sizes)
  shake_test_vo_dir(exe, './data/nist/shake_bytes/', shake_sizes)
  print('-- Success')