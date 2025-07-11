import tempfile
import functools
import argparse
from config import *
from utils import *

def extract_all_features_from_memdump(memdump_path, CSVoutput_path, volatility_path):
    features = {}
    print('=> Outputting to', CSVoutput_path)

    with tempfile.TemporaryDirectory() as workdir:
        vol = functools.partial(invoke_volatility3, volatility_path, memdump_path)
        for module, extractor in VOL_MODULES.items():
            print('=> Executing Volatility module', repr(module))
            output_file_path = os.path.join(workdir, module)
            vol(module, output_file_path)
            with open(output_file_path, 'r') as output:
                features.update(extractor(output))
    
    features_mem = {'mem.name_extn': str(memdump_path).rsplit('/', 1)[-1]}
    features_mem.update(features)

    file_path = os.path.join(CSVoutput_path, 'output.csv')
    write_dict_to_csv(file_path,features_mem,memdump_path)

    print('=> All done')

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-f','--memdump',default=None, help='Path to folder/directory which has all memdumps',required = True)
    p.add_argument('-o', '--output', default=None, help='Path to the folder where to output the CSV',required = True)
    p.add_argument('-V', '--volatility', default=None, help='Path to the vol.py file in Volatility folder including the extension .py',required = True)
    return p, p.parse_args()


if __name__ == '__main__':
    p, args = parse_args()

    #print(args.memdump)
    folderpath = str(args.memdump)
    file_list = sorted(os.listdir(folderpath), key=lambda x: -os.path.getmtime(os.path.join(folderpath, x)), reverse=True)

    print(folderpath)

    for filename in file_list:
        print("==> Now resolving features for : ",filename)
        print()
        file_path = os.path.join(folderpath, filename)
        #print(file_path)

        if (file_path).endswith('.raw') or (file_path).endswith('.mem') or (file_path).endswith('.vmem') or (file_path).endswith('.mddramimage'):
            extract_all_features_from_memdump((file_path), args.output, args.volatility)
