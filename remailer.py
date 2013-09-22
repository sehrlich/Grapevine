# REMAILER FORMATTED MESSAGE FOR address
# # (This is encrypted to public key)
# # RECIPIENTS
# # ADDRESS
# # to_addr   delay
# # public_key
# # ADDRESS
# # to_addr'  delay'
# # public_key''
# # ADDRESS
# # to_addr'' delay''
# # public_key''
# # OPTIONS
# #     SIGN, LOG?, IGNORE?, 
# #     SPLIT_MESSAGE to find message encrypted to several people?
# #     COMMENTS 
# # MESSAGE
# # message

# this is rough right now, and a sample will live in sample...

# Protocol
# Receive message.
# Decrypt to Remailer:encrypted
# Decrypt to RECIPIENTS:OPTIONS:MESSAGE
# Follow OPTIONS, reencrypt MESSAGE for RECIPIENTS

# TODO FIXME change all the formatting stuff to magic_constants
import GnuPGInterface

def process_message(incoming_message):
    """This is for a mail server to process and resend an encrypted message"""
    # Next line is temporary -- whoever calls this should be responsible for stripping the first line indicating that it is a remailer message
    incoming_message=incoming_message.split('\n',1)[1]
    decrypted_message = decrypt(incoming_message)
    #return parse_message(decrypted_message)
    (recipients,options,message) = parse_message(decrypted_message)
    
    #Check if there are options that 
    for (send_to_next_address, public_key, delay) in recipients:
        encrypted_message = encrypt(message,public_key)
        remailer_message = "REMAILER FORMATTED MESSAGE FOR " + send_to_next_address + encrypted_message
        send_message(remailer_message, send_to_next_address, delay)
    return (send_to_next_address, encrypted_message, delay)

def parse_message(decrypted_message):
    """ Takes an inner message and returns the appropriate addresses, flags, and the message itself"""
    lines = decrypted_message.split('\n')
    tmpstring =''
    recipients = []
    options = []
    state = 'neutral'
    for l in lines:
        if state == 'reading' or state == 'msg':
            if 'END' in l:
                if 'MESSAGE' in l:
                    message = tmpstring
                else:
                    recipients[0] += [tmpstring]
                tmpstring=''
                state = 'neutral'
            else:
                tmpstring+=l
        elif state == 'get_address':
            add,delay= l.split()
            recipients = [[add,int(delay)]] + recipients
            state = 'neutral'
        elif state == 'opts':
            state = 'neutral'
        elif state == 'neutral':
            if l == 'ADDRESS':
                state = 'get_address'
            elif l == '-----BEGIN PGP PUBLIC KEY BLOCK-----':
                state = 'reading'
            elif l == 'OPTIONS':
                state = 'opts'
            elif l == 'BEGIN_MESSAGE':
                state = 'msg'
    return (recipients,options,message)

def send_message(address, message, delay=0):
    """Send message to address after delay seconds"""
    print 'To:',address
    print 'Message:\n',message

def wrap_message(message, destination_address, destination_key):
    """The message should be already encrypted when passed to this function. This takes a routing plan and encrypts the messages and public keys so that the will be correctly processed by process message routine."""
    # may want to make the route passed in as well
    (structure,route) = generate_route(destination_address, destination_key)
    wrapped_message = message
    wrapped_address = ''
    begin_block = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n'
    end_block = '-----END PGP PUBLIC KEY BLOCK-----\n'
    # ultimately, we should support multiple messages (and a specification of which to forward where, or even include the message to forward next to the public key
    # and should be able to wrap up arbitrary dags
    if structure=="linear":
        wrapper = "RECIPIENTS\n%(recipient_block)s\nOPTIONS\n%(option_block)s\nBEGIN_MESSAGE\n%(message_block)s\nEND MESSAGE"
        # This is what we're implementing first
        for (address, public_key) in route:
           encrypted_to = encrypt(wrapped_message, public_key)
           # temporarily addednewline before end_block
           send_to = "ADDRESS\n%s %d\n%s%s\n%s\n"  \
               %(address, 0, begin_block, public_key, end_block)
           options = ""
           wrapped_address = address
           wrapped_message = wrapper % \
                   {"recipient_block":send_to, \
                    "option_block":options, \
                    "message_block":encrypted_to}
           wrapped_message = encrypt(wrapped_message, public_key)
           wrapped_message = "REMAILER FORMATTED MESSAGE FOR %s\n%s" % (wrapped_address, wrapped_message)
    return wrapped_message

def generate_route(destination_address, destination_key):
    """Plots a route (for the moment just a list of addresses and their public keys)."""
    return ("linear",[(destination_address, destination_key)])


### This is building an encryption key for testing purposes

def encrypt(message, key):
    """Encrypt message to public key using GPG."""
    gnupg = GnuPGInterface.GnuPG()
    gnupg.options.armor = 1
    gnupg.options.meta_interactive = 0
    tmpkey = gnupg.import_key(key)
    fp = tmpkey.fingerprints[0]

    gnupg.options.recipients = [fs]
    proc = gnupg.run(['--encrypt'],create_fhs['stdin','stdout'])

    proc.handles['stdin'].write(message)
    proc.handles['stdin'].close()
    
    ciphertext = proc.handles['stdout'].read()
    proc.handles['stdout'].close()
    
    proc.wait()

    # We don't want to store the key
    gnupg.delete_keys(fp)
    return ciphertext

def decrypt(message):
    return message[11:]



