import GnuPGInterface

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


