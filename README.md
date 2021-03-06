# Cellular Vehicle-to-Everything (C-V2X) Mode 4 Communication Model for ns-3

(Please find the original README below.)

This project was forked from [https://github.com/FabianEckermann/ns-3_c-v2x](https://github.com/FabianEckermann/ns-3_c-v2x) and provides the same functions, but bindings for Python 3.8 are fixed.

I also added a simple method to compile the code:

This will take some time. A Docker container that contains all relevant requirements will be created and the build starts automatically. Also note that the first compilation will fail as the Bindings cannot be completely generated. A fix will be applied by the script and it will continue to compile ns-3, which should be successful now.

```sh
cd ns-3_c-v2x
./compile.sh
cd ..
```

If the build container is not close automatically, leave it by calling `exit`.

---------------------


# Cellular Vehicle-to-Everything (C-V2X) Mode 4 Communication Model for ns-3

A ns-3 model for C-V2X Mode 4 communication based on the ns-3 D2D model from [NIST](https://github.com/usnistgov/psc-ns3/tree/d2d-ns-3.22).

## Installation

1. Clone or download the source code from this repository
2. Navigate to the root directory of the cloned/downloaded repository
3. Configure the project using the command
```
   ./waf configure
```
4. Build the project using the command
```
   ./waf build
```

For more details regarding the configuration and building of ns-3 projects see [the ns-3 documentation](https://www.nsnam.org/documentation/).

## Usage

A example script for the usage of the C-V2X Mode 4 is located in the *scratch* directory of this repository (*v2x_communication_example.cc*).
To run the example script run:
```
   ./waf --run v2x_communication_example
```

# Cite as

If you use our model in your research, please cite the following paper:

F. Eckermann, M. Kahlert, C. Wietfeld, ["Performance Analysis of C-V2X Mode 4 Communication Introducing an Open-Source C-V2X Simulator"](https://www.kn.e-technik.tu-dortmund.de/.cni-bibliography/publications/cni-publications/Eckermann2019performance.pdf), In 2019 IEEE 90th Vehicular Technology Conference (VTC-Fall), Honolulu, Hawaii, USA, September 2019. (accepted for presentation).

### Bibtex:
    @InProceedings{Eckermann2019performance,
        Author = {Fabian Eckermann and Moritz Kahlert and Christian Wietfeld},
        Title = {Performance Analysis of {C-V2X} Mode 4 Communication Introducing an Open-Source {C-V2X} Simulator},
        Booktitle = {2019 IEEE 90th Vehicular Technology Conference (VTC-Fall)},
        Year = {2019},
        Publishingstatus = {accepted for presentation},
        Address = {Honolulu, Hawaii, USA},
        Month = {September},
    }
