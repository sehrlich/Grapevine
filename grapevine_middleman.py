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
