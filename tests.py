import subprocess

test_algorithms = ['1', '224', '256', '384', '512', '512_224', '512_256']
formats_per_test = ['ShortMsg', 'LongMsg']

tests_directory = './data/nist/sha1_2_bits/'

for alg in test_algorithms:
  for format in formats_per_test:
    file = open(tests_directory + 'SHA' + alg + format + '.rsp')
    while True:
      line = 't'
      while(line != '' and not line.startswith('Len')): line = file.readline()
      if(line == ''): break

      len: int = int(line.split(' = ')[1])
      msg: str = file.readline().split(' = ')[1].strip()
      md: str = file.readline().split(' = ')[1].strip()

      print('Running: ./test.exe %s %d %s -- ' % (alg, len, msg), end='')
      result = subprocess.run(['./test.exe', alg, str(len), msg], stdout=subprocess.PIPE)
      result_md = result.stdout.decode('utf-8').strip()
      if(result_md != md): 
        print('Failed:', alg, format)
        print('\t len =', len)
        print('\t msg =', msg)
        print('\t expected md =', md)
        print('\t actual   md =', result_md)
        exit(1)
      else:
        print('Success:', alg, format)


