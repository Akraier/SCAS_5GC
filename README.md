     @@@@@@    @@@@@@@   @@@@@@    @@@@@@    @@@@@@@   @@@@@@   @@@  @@@                   @@@@@@@   @@@@@@@@  
    @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@                   @@@@@@@  @@@@@@@@@  
    !@@       !@@       @@!  @@@  !@@       !@@       @@!  @@@  @@!@!@@@                   !@@      !@@        
    !@!       !@!       !@!  @!@  !@!       !@!       !@!  @!@  !@!!@!@!                   !@!      !@!        
    !!@@!!    !@!       @!@!@!@!  !!@@!!    !@!       @!@!@!@!  @!@ !!@!     @!@!@!@!@     !!@@!!   !@! @!@!@  
     !!@!!!   !!!       !!!@!!!!   !!@!!!   !!!       !!!@!!!!  !@!  !!!     !!!@!@!!!     @!!@!!!  !!! !!@!!  
         !:!  :!!       !!:  !!!       !:!  :!!       !!:  !!!  !!:  !!!                       !:!  :!!   !!: 
        !:!   :!:       :!:  !:!      !:!   :!:       :!:  !:!  :!:  !:!                       !:!  :!:   !::
    :::: ::    ::: :::  ::   :::  :::: ::    ::: :::  ::   :::   ::   ::                   :::: ::   ::: ::::  
    :: : :     :: :: :   :   : :  :: : :     :: :: :   :   : :  ::    :                    :: : :    :: :: :  

# SCAScan-5GC
A lightweight Python framework for automating Security Assurance testing of 5G Core networks, aligned with 3GPP SCAS specifications.

At the current stage SCAScan-5GC is just at the beginning of its process. It's main purpose is to provide automated security assurance on your 5G Core development, helping the community with free test implementation. In this version, only some AMF test cases are implemented, but future versions - in case the project gains curiosity from the community - wants to expand the coverage on many more NFs until the whole Core Network is tested. 
The behavior of the framework has been tested on docker version of the main Open Source development of 5G, Free5GC, Open5GS, OpenAirInterface.

## Install

```bash 
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
git clone https://github.com/Akraier/SCAS_5GC.git
```

### Configure Free5gc
Install Free5GC compose following https://free5gc.org/guide/0-compose/
```bash
cd SCAS_5GC
cp conf/free5gc/docker-compose.yaml ~/free5gc-compose/
cp mitm_proxy ~/free5gc-compose/
```

### Configure Open5gs

```bash
git clone https://github.com/herlesupreeth/docker_open5gs.git
cd SCAS_5GC
cp conf/open5gs/my_deploy.yaml ~/docker_open5gs/
cp conf/open5gs/ueransim-gnb.yaml ~/docker_open5gs/ueransim/
cp mitm_proxy ~/docker_open5gs
cp
```
### Configure OpenAirInterface
```bash 
git clone https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-fed.git
cd SCAS_5GC
cp conf/oai/docker-compose-oai-scascan5g.yaml ~/oai-cn5g-fed/docker-compose/
cp mitm_proxy ~/oai-cn5g-fed/docker-compose/
cp -r conf/oai/ueransim ~/oai-cn5g-fed/docker-compose/
cp conf/oai/gnbcfg.yaml ~/oai-cn5g-fed/docker-compose/conf/
cp conf/oai/uecfg.yaml ~/oai-cn5g-fed/docker-compose/conf/
cp conf/oai/basic_nrf_config.yaml ~/oai-cn5g-fed/docker-compose/conf/
cp conf/oai/oai_db2.sql ~/oai-cn5g-fed/docker-compose/database/

```


