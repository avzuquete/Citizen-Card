# PAM library to authenticate a person using their Citizen Card (Cartão de Cidadão)

Follow these steps to compile this PAM module in a Linux system:

1. Install the CC software package from the official distribution site (https://www.autenticacao.gov.pt/cc-aplicacao).
2. Install all the packages referred in the CC's installation information.
3. Test if the tools already included in the package work with your CC (**pteidgui**, etc.).
4. Install some packages required by this tool:
    * **libopencryptoki-dev**
5. Run the
```
make
```
   command. It will create a PAM module (**pam_PTEIDCC.so**) and an auxiliary tool (**addCCuser** binary). This command should be used to register new users that are to be authenticated using their CC and the PAM module.
6. Run the command
```
make install
```
   as super-user. It will install the PAM module in the expected directory. It will also create, if absent, a directory (**/etc/CC**) for storing the users' public keys.
