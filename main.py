import tempfile
import functools
import argparse
from config import *
import networkx as nx
from utils import *

plugin_folder_path = "D:\Vol_Results\AllPluginsJSON"

def dropStr_to_dropList(drop_list_str):
    if not drop_list_str or not drop_list_str.strip():
        raise ValueError("No module name provided for elimination.")
    
    raw_items = drop_list_str.split(",")
    dropped_modules = {item.strip().lower() for item in raw_items if item.strip()}

    # Check for unknown modules (not in VOL_MODULES)
    invalid_modules = dropped_modules - VOL_MODULES.keys()
    if invalid_modules:
        raise ValueError(
            f"The following modules are not recognized Volatility modules: {sorted(invalid_modules)}.\n"
            f"Valid Volatility modules are: {sorted(VOL_MODULES.keys())}")

    # Check if any dropped modules are actually required
    protected_modules = dropped_modules.intersection(BASE_VOL_MODULES)
    if protected_modules:
        raise ValueError(
            f"The following modules are required and cannot be dropped: {sorted(protected_modules)}.\n"
            f"Required modules are: {sorted(BASE_VOL_MODULES)}")
    return dropped_modules



def build_plugin_dag(vol_modules, plugin_deps):
    G = nx.DiGraph()

    for plugin in vol_modules:
        G.add_node(plugin)
    for plugin, deps in plugin_deps.items():
        for dep in deps:
            G.add_edge(dep, plugin)

    return list(nx.topological_sort(G))


def extract_all_features_from_memdump(memdump_path, CSVoutput_path, volatility_path, drop_list):
    features = {}
    context = {}
    print('=> Outputting to', CSVoutput_path)

    dropped_modules = dropStr_to_dropList(drop_list)

    with tempfile.TemporaryDirectory() as workdir:
        vol = functools.partial(invoke_volatility3, volatility_path, memdump_path)
               
        for module, extractor in VOL_MODULES.items():
            if module.lower() in dropped_modules:
                print(f'=> Skipping module: {module}')
                continue
            print('=> Executing Volatility module', repr(module))
            # output_file_path = os.path.join(workdir, module)
            # vol(module, output_file_path)

            module_pre_output_name = module.replace('.','_')
            file_list = [filename for filename in os.listdir(plugin_folder_path) if (f'windows_{module_pre_output_name}') in filename]
           
            if len(file_list) != 0:
                # output = output_file_path[0]
                output = os.path.join(plugin_folder_path, [filename for filename in os.listdir(plugin_folder_path) if (f'windows_{module_pre_output_name}') in filename][0])
            else: 
                continue  


            # deps = PLUGIN_DEPENDENCIES.get(module, [])
            # kwargs = {dep: context[dep] for dep in deps if dep in context}

            # result = extractor(output, **kwargs)
            # print(result, type(result))
            # if isinstance(result, list) and isinstance(result[1], dict):
            #     data, feat = result
            #     features.update(feat)
            #     context[module] = data
            # elif isinstance(result, dict):
            #     features.update(result)
            # else:
            #     raise ValueError(f"Extractor for {module} returned unexpected format")


            if module == 'info':
                module_features = extractor(output)
                DUMP_TIME = module_features.get('info.SystemTime') or None
                features.update(module_features)
            
            elif module == 'pslist':
                module_features = extractor(output)
                PID_LIST = module_features[0]
                features.update(module_features[1])

            elif module == 'registry.hivelist':
                module_features = extractor(output)
                HIV_OFFSETS = module_features[0]
                features.update(module_features[1])
                
            elif module == 'registry.hivescan':
                module_features = extractor(output, HIV_OFFSETS)
                features.update(module_features)

            elif module == 'threads':
                module_features = extractor(output)
                THR_OFFSETS = module_features[0]
                features.update(module_features[1])

            elif module == 'thrdscan':
                module_features = extractor(output, THR_OFFSETS)    
                features.update(module_features)

            elif module == 'deskscan':
                module_features = extractor(output, PID_LIST)
                features.update(module_features)

            elif module == 'amcache':
                module_features = extractor(output, DUMP_TIME)
                features.update(module_features)
        
            else:
                module_features = extractor(output)
                features.update(module_features)

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
    p.add_argument('-D', '--drop', default=None, help='Plugin names to drop from the features list',required = False)
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
            extract_all_features_from_memdump((file_path), args.output, args.volatility, args.drop)

        break