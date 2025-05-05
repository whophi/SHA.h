import subprocess

formats_per_test = ['ShortMsg', 'LongMsg']
sha_sizes_1_2 = ['1', '224', '256', '384', '512', '512_224', '512_256']
sha_sizes_3 = ['3_224', '3_256', '3_384', '3_512']
sha_sizes_3 = ['3_224', '3_256', '3_384', '3_512']
shake_sizes = ['128', '256']

PRINT_SUCCESS: bool = False


def sha_test_dir(dir: str, prepend: str, sizes, is_shake: bool = False):
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
        if PRINT_SUCCESS: print('Running: ./test.exe %s %d %s -- ' % (alg_str, len, msg), end='')
        result = subprocess.run(['./test.exe', alg_str, str(len), msg], stdout=subprocess.PIPE)
        result_md = result.stdout.decode('utf-8').strip()
        if(result_md != md): 
          if not PRINT_SUCCESS:
            print('Running: ./test.exe %s %d %s -- ' % (alg_str, len, msg), end='')
          print('Failed:', alg_str, format)
          print('\t len =', len)
          print('\t msg =', msg)
          print('\t expected md =', md)
          print('\t actual   md =', result_md)
          exit(1)
        elif PRINT_SUCCESS:
          print('Success:', alg_str, format)

def shake_test_vo_dir(dir: str, sizes):
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
        if PRINT_SUCCESS: print('Running: ./test.exe %s %d %s %s -- ' % (alg_str, len, msg, out_len), end='')
        result = subprocess.run(['./test.exe', alg_str, str(len), msg, out_len], stdout=subprocess.PIPE)
        result_md = result.stdout.decode('utf-8').strip()
        if(result_md != md):
          if not PRINT_SUCCESS:
            print('Running: ./test.exe %s %d %s %s -- ' % (alg_str, len, msg, out_len), end='')
          print('Failed:', alg_str, format)
          print('\t len =', len)
          print('\t msg =', msg)
          print('\t out_len =', out_len)
          print('\t expected md =', md)
          print('\t actual   md =', result_md)
          exit(1)
        elif PRINT_SUCCESS:
          print('Success:', alg, format)

print("Testing SHA1/2")
sha_test_dir('./data/nist/sha1_2_bits/', 'SHA', sha_sizes_1_2)
sha_test_dir('./data/nist/sha1_2_bytes/', 'SHA', sha_sizes_1_2)
print("Testing SHA3")
sha_test_dir('./data/nist/sha3_bits/', 'SHA', sha_sizes_3)
sha_test_dir('./data/nist/sha3_bytes/', 'SHA', sha_sizes_3)
print("Testing Shake msg size")
sha_test_dir('./data/nist/shake_bits/', 'SHAKE', shake_sizes, True)
sha_test_dir('./data/nist/shake_bytes/', 'SHAKE', shake_sizes, True)
print("Testing Shake out size")
shake_test_vo_dir('./data/nist/shake_bits/', shake_sizes)
shake_test_vo_dir('./data/nist/shake_bytes/', shake_sizes)