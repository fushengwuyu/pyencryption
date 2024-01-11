# author: sunshine
# datetime:2024/1/8 下午5:43
import setuptools
with open("readme.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="encryptKit",
    version="0.2",
    author="sunshine",
    author_email="",
    description="python project encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fushengwuyu/pyencryption",
    packages=setuptools.find_packages(),
    install_requires=["pydantic", "pycryptodome", "M2Crypto", "Cython"],
    entry_points={
        'console_scripts': [
            'douyin_image=douyin_image:main'
        ],
    },
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
