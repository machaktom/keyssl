import argparse
import os.path
import subprocess as sub


# Get file type based on extension. Only .p12 and .jks are supported
def file_type(filename):
    if filename.endswith('.p12'):
        return 'PKCS12'
    elif filename.endswith('.jks'):
        return 'JKS'
    else:
        return 'JKS'


# Get file name without extension
def filename_without_extension(file_name):
    if file_type(file_name) in ['PKCS12', 'JKS']:
        return file_name[:len(file_name)-4]
    else:
        return file_name


# Command (function) to run in interactive or non-interactive mode
def run_command(command_function, is_interactive):
    if is_interactive is None:
        return command_function()
    else:
        input_ = raw_input("Skip this command? (y/N):")
        if input_ == 'y':
            print 'Command skipped'
        elif input_ in ['n', '']:
            return command_function()
        else:
            print 'Please enter \'y\' or \'n\''


# Run system command to convert a keystore to PKCS12
def run_convert_to_pkcs12(args):
    command = ['keytool',
               '-importkeystore',
               '-srckeystore',
               _base_name + '.jks',
               '-srcstoretype',
               args.inform
               if args.inform is not None
               else file_type(args.in_),
               '-destkeystore',
               _base_name + '.p12',
               '-deststoretype',
               'PKCS12']

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output

    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


# Run system command to convert a keystore to JKS
def run_convert_to_jks(args):
    command = ['keytool',
               '-importkeystore',
               '-srckeystore',
               _base_name + '.p12',
               '-srcstoretype',
               args.inform
               if args.inform is not None
               else file_type(args.in_),
               '-destkeystore',
               _base_name + '.jks',
               '-deststoretype',
               'JKS']

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


# Run system command to extract private keys from PKCS12 keystore
def run_extract_private_key(args):
    command = ['openssl',
               'pkcs12',
               '-in',
               _base_name + '.p12',
               '-nocerts',
               '-out',
               _base_name + '.key']

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


# Run system command to convert private key to non-encrypted key
def run_convert_private_key_into_nonencrypted(args):
    if not os.path.isfile(_base_name + '.key'):
        run_extract_private_key(args)
    command = ['openssl',
               'rsa',
               '-in',
               _base_name + '.key',
               '-out',
               _base_name + '.noenc.key']

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


# Run system command to extract certificate chain from PKCS12 keystore
def run_extract_certificate_chain(args):
    command = ['openssl',
               'pkcs12',
               '-in',
               _base_name + '.p12',
               '-nokeys',
               '-out',
               _base_name + '.chain.pem']

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


# Run system command to converts PEM certificates to DER
def run_convert_certs_to_der(args):
    if certs_count == 0:
        run_split_certificate_chain(args)
    for x in range(0, certs_count):
        command = ['openssl',
                   'x509',
                   '-in',
                   _base_name + '.' + str(x) + '.pem',
                   '-inform',
                   'PEM',
                   '-outform',
                   'DER',
                   '-out',
                   _base_name + '.' + str(x) + '.der']

        def command_function():
            p = sub.Popen(command)
            output, errors = p.communicate()
            print output
        print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
        run_command(command_function, args.interactive)


# Returns system command as string to extract certificates from PEM encoded certificate chain
def run_split_certificate_chain(args):
    def command_function():
        if not os.path.isfile(_base_name + '.chain.pem'):
            run_extract_certificate_chain(args)
        with open(_base_name + '.chain.pem', 'r') as cert_chain_file:
            current_cert_file = None
            cert_index = 0
            for line in cert_chain_file:
                if current_cert_file is not None:
                    current_cert_file.write(line)
                if 'BEGIN CERTIFICATE' in line:
                    current_cert_file = open(_base_name + '.' + str(cert_index) + '.pem', 'w')
                    current_cert_file.write(line)
                if 'END CERTIFICATE' in line:
                    current_cert_file.close()
                    current_cert_file = None
                    cert_index += 1
            certs_count = cert_index
        cert_chain_file.close()
        return certs_count
    print '\n-- KeySSL -- Next command to be run is splitting the certificate chain into separate files\n'
    return run_command(command_function, args.interactive)


# Main
parser = argparse.ArgumentParser(description='Run a KeySSL command')
parser.add_argument('command',
                    choices=['pkcs12', 'jks'],
                    help='KeySSL command')
parser.add_argument('-in',
                    dest='in_',
                    help='Input file name')
parser.add_argument('-interactive',
                    dest='interactive',
                    action='store_const',
                    const=True,
                    help='Interactive mode')
parser.add_argument('-inform',
                    choices=['PKCS12', 'JKS'],
                    dest='inform',
                    default=None,
                    help='Input file type')
parser.add_argument('-nokeys',
                    action='store_const',
                    const=True,
                    help='Disable extraction of private keys the key-store')
parser.add_argument('-nodecryptedkeys',
                    action='store_const',
                    const=True,
                    help='Disable extracting keys into non-encrypted file')
parser.add_argument('-nocerts',
                    action='store_const',
                    const=True,
                    help='Disable extraction of certificate chain from the key-store')
parser.add_argument('-nosplitchain',
                    action='store_const',
                    const=True,
                    help='Disable splitting of certificate chain from the key-store into certificates. This option '
                         'overrides the -nocerts option')
parser.add_argument('-noder',
                    action='store_const',
                    const=True,
                    help='Disable conversion of certificates from the key-store into binray format. This option '
                         'overrides the -nosplitchain option')
args = parser.parse_args()
print args

_base_name = filename_without_extension(args.in_)
if args.command == 'jks':
    run_convert_to_pkcs12(args)
if args.command == 'pkcs12':
    run_convert_to_jks(args)
certs_count = 0

if not args.nokeys:
    run_extract_private_key(args)
if not args.nodecryptedkeys:
    run_convert_private_key_into_nonencrypted(args)
if not args.nocerts:
    run_extract_certificate_chain(args)
if not args.nosplitchain:
    certs_count = run_split_certificate_chain(args)
if not args.noder:
    run_convert_certs_to_der(args)



