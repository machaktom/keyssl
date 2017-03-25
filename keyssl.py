import argparse
import os.path
import subprocess as sub
from enum import Enum


class Tool(Enum):
    OPENSSL = 'openssl'
    KEYTOOL = 'keytool'


def __get_file_type(file_name):
    """ Get file type by filename extension. Can be 'PKCS12' or 'JKS' """
    if file_name.endswith('.p12'):
        return 'PKCS12'
    elif file_name.endswith('.jks'):
        return 'JKS'
    else:
        return 'JKS'


def __get_filepath_without_extension(file_name):
    """ Get the name without extension e.g 'keystore_file' from 'keystore_file.jks'"""
    if __get_file_type(file_name) in ['PKCS12', 'JKS']:
        return file_name[:len(file_name)-4]
    else:
        return file_name


def run_command(command_function, is_interactive):
    """ Run command_function in interactive or non-interactive mode """
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


def __parse_optional_password_args(command, args):
    """ Handle password arguments if they need to be added to the specified command """
    if args.pass_io is not None:
        if command[0] == Tool.KEYTOOL:
            command.append("-srcstorepass")
            command.append(args.pass_io)
        elif command[0] == Tool.OPENSSL:
            command.append("-passin")
            command.append("pass:" + args.pass_io)
        else:
            raise AttributeError("Attribute 'command' has to be one of: " + Tool.KEYTOOL + " or " + Tool.OPENSSL)
    elif args.in_pass is not None:
        command.append("-srcstorepass")
        command.append(args.pass_in)

    if args.pass_io is not None:
        if command[0] == Tool.KEYTOOL:
            command.append("-deststorepass")
            command.append(args.pass_io)
        elif command[0] == Tool.OPENSSL:
            command.append("-passout")
            command.append("pass:" + args.pass_io)
        else:
            raise AttributeError("Attribute 'command' has to be one of: 'keytool' or 'openssl'")

    elif args.out_pass is not None:
        command.append("-deststorepass")
        command.append(args.pass_out)


def run_convert_to_pkcs12(args):
    """ Create and run system command to convert a keystore to PKCS12 """
    command = [Tool.KEYTOOL,
               '-importkeystore',
               '-srckeystore',
               _filepath_without_extension + '.jks',
               '-srcstoretype',
               args.inform
               if args.inform is not None
               else __get_file_type(args.in_),
               '-destkeystore',
               _filepath_without_extension + '.p12',
               '-deststoretype',
               'PKCS12']

    __parse_optional_password_args(command, args)

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


def run_convert_to_jks(args):
    """ Create and run system command to convert a keystore to JKS """
    command = [Tool.KEYTOOL,
               '-importkeystore',
               '-srckeystore',
               _filepath_without_extension + '.p12',
               '-srcstoretype',
               args.inform
               if args.inform is not None
               else __get_file_type(args.in_),
               '-destkeystore',
               _filepath_without_extension + '.jks',
               '-deststoretype',
               'JKS']

    __parse_optional_password_args(command, args)

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


def run_convert_to_pem_keystore(args):
    """ Create and run system command to convert to pem keystore """
    command = [Tool.OPENSSL,
               'pkcs12',
               '-in',
               _filepath_without_extension + '.p12',
               '-out',
               _filepath_without_extension + '.keystore.pem']

    __parse_optional_password_args(command, args)

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


def run_extract_private_key(args):
    """ Create and run system command to extract private keys from PKCS12 keystore """
    command = [Tool.OPENSSL,
               'pkcs12',
               '-in',
               _filepath_without_extension + '.p12',
               '-nocerts',
               '-out',
               _filepath_without_extension + '.key']

    __parse_optional_password_args(command, args)

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


def run_convert_private_key_into_nonencrypted(args):
    """ Create and run system command to convert private key to non-encrypted key """
    if not os.path.isfile(_filepath_without_extension + '.key'):
        run_extract_private_key(args)
    command = [Tool.OPENSSL,
               'rsa',
               '-in',
               _filepath_without_extension + '.key',
               '-out',
               _filepath_without_extension + '.noenc.key']

    __parse_optional_password_args(command, args)

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


def run_extract_certificate_chain(args):
    """ Create and run system command to extract certificate chain from PKCS12 keystore """
    command = [Tool.OPENSSL,
               'pkcs12',
               '-in',
               _filepath_without_extension + '.p12',
               '-nokeys',
               '-out',
               _filepath_without_extension + '.chain.pem']

    __parse_optional_password_args(command, args)

    def command_function():
        p = sub.Popen(command)
        output, errors = p.communicate()
        print output
    print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
    run_command(command_function, args.interactive)


def run_convert_certs_to_der(args):
    """ Create and run system command to converts PEM certificates to DER """
    if certs_count == 0:
        run_split_certificate_chain(args)
    for x in range(0, certs_count):
        command = [Tool.OPENSSL,
                   'x509',
                   '-in',
                   _filepath_without_extension + '.' + str(x) + '.pem',
                   '-inform',
                   'PEM',
                   '-outform',
                   'DER',
                   '-out',
                   _filepath_without_extension + '.' + str(x) + '.der']

        def command_function():
            p = sub.Popen(command)
            output, errors = p.communicate()
            print output
        print '\n-- KeySSL -- Next command to be run is:\n' + ' '.join(command)
        run_command(command_function, args.interactive)


def run_split_certificate_chain(args):
    """ Create and run system command to extract certificates from PEM encoded certificate chain """
    def command_function():
        if not os.path.isfile(_filepath_without_extension + '.chain.pem'):
            run_extract_certificate_chain(args)
        with open(_filepath_without_extension + '.chain.pem', 'r') as cert_chain_file:
            current_cert_file = None
            cert_index = 0
            for line in cert_chain_file:
                if current_cert_file is not None:
                    current_cert_file.write(line)
                if 'BEGIN CERTIFICATE' in line:
                    current_cert_file = open(_filepath_without_extension + '.' + str(cert_index) + '.pem', 'w')
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
parser.add_argument('-passio',
                    dest='pass_io',
                    help='Input and output password (overrides \'pass_in\' and \'pass_out\'',
                    default=None)
parser.add_argument('-passin',
                    dest='pass_in',
                    help='Input password',
                    default=None)
parser.add_argument('-passout',
                    dest='pass_out',
                    help='Output password',
                    default=None)
parser.add_argument('-nopemkeystore',
                    action='store_const',
                    const=True,
                    help='Disable conversion to PEM keystore')
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
                    help='Disable conversion of certificates from the key-store into binary format. This option '
                         'overrides the -nosplitchain option')
args = parser.parse_args()
print args

_filepath_without_extension = __get_filepath_without_extension(args.in_)
if args.command == 'jks':
    run_convert_to_pkcs12(args)
if args.command == 'pkcs12':
    run_convert_to_jks(args)
certs_count = 0

if not args.nopemkeystore:
    run_convert_to_pem_keystore(args)
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



