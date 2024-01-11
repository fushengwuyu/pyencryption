# author: sunshine
# datetime:2024/1/3 下午3:20

import os, time, shutil
from distutils.core import setup
from Cython.Build import cythonize
from setuptools import find_packages
import argparse

parser = argparse.ArgumentParser(description='encrypt project')
parser.add_argument("--except_dirs", help="except dirs", default='', type=str, nargs='+')
parser.add_argument("--enc_dir", help="enc dir", default='/opt/sunshine/deploy/Dml/operator', type=str)
parser.add_argument("--build_dir", help="build_dir", default='/opt/sunshine/deploy/Dml/operator_enc', type=str)
parser.add_argument("--entrance", help="entrance", default='run.py', type=str)

args = parser.parse_args()

start_time = time.time()

curr_dir = args.enc_dir

except_dirs = args.except_dirs
# excepts = []
# for d in except_dirs:
#     for root, dirs, files in os.walk(d):
#         for file in files:
#             excepts.append(os.path.join(root, file))

build_dir = args.build_dir
build_tmp_dir = build_dir + "/temp"

s = "# cython: language_level=3"
entrance = args.entrance


def get_py(base_path=os.path.abspath('..'), excepts=(), delC=False):
    pys = []
    for root, dirs, files in os.walk(base_path):
        if any([root.__contains__(e) for e in excepts]):
            continue

        for file in files:
            filename = os.path.join(root, file)
            ext = os.path.splitext(filename)[1]
            if ext == ".c":
                if delC and os.stat(filename).st_mtime > start_time:
                    os.remove(filename)
            elif filename not in excepts and os.path.splitext(filename)[1] not in ('.pyc', '.pyx'):
                if os.path.splitext(filename)[1] == '.py' and not filename.startswith('__'):
                    pys.append(filename)
    return pys


def pack_pyd():
    # 获取py列表
    module_list = get_py(base_path=curr_dir, excepts=except_dirs, delC=True)
    for l in module_list:
        print(l)
    try:
        setup(
            ext_modules=cythonize(module_list, compiler_directives={'language_level': "3"}),
            script_args=["build_ext", "-b", build_dir, "-t", build_tmp_dir],
            packages=find_packages(),
        )
    except Exception as ex:
        print("error! ", str(ex))
    if os.path.exists(build_tmp_dir):
        shutil.rmtree(build_tmp_dir)

    print("complate! time:", time.time() - start_time, 's')


def delete_c(path='.'):
    '''
    删除编译过程中生成的.c文件
    :param path:
    :param excepts:
    :return:
    '''
    try:
        dirs = os.listdir(path)
        for dir in dirs:
            new_dir = os.path.join(path, dir)
            if os.path.isfile(new_dir):
                ext = os.path.splitext(new_dir)[1]
                if ext == '.c':
                    os.remove(new_dir)
            elif os.path.isdir(new_dir):
                delete_c(new_dir)
    except Exception as e:
        print(e)
        return


def copy_file():
    """
    将非空__init__.py和非py文件拷贝到相应的位置中
    """
    for root, dirs, files in os.walk(curr_dir):
        if root.__contains__('.idea'):
            continue
        if root.__contains__(build_dir):
            continue
        if root.__contains__('__pycache__'):
            continue
        base_root = root.lstrip(curr_dir).lstrip('/')
        for file in files:
            if not file.endswith(('.py', '.pyc', '.c')) or file == '__init__.py' or file == entrance:
                src = os.path.join(root, file).replace('./', '')
                # if not os.path.exists(os.path.join(build_dir, root)):
                #     # 级联创建目录
                os.makedirs(os.path.join(build_dir, base_root), exist_ok=True)

                dst = os.path.join(build_dir, os.path.join(base_root, file).replace('./', ''))
                shutil.copyfile(src, dst)


def main():
    try:
        pack_pyd()
    except Exception as e:
        print(str(e))
    finally:
        delete_c(curr_dir)
    try:
        copy_file()
    except Exception as e:
        print(e)


if __name__ == '__main__':
    main()
