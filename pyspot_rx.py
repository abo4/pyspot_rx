"""
Python script to listen on amateur radio via
    BrandMeister network and
    Open Terminal Protocol
License: GPL-3.0
"""
import asyncio
import argparse
import configparser
import subprocess
import serial
import hashlib
from datetime import datetime
import readline
from re import split
from distutils.spawn import find_executable
from select import select
from time import time
import os
import socket
import _pickle as pickle
import logging
log_formatter = logging.Formatter('%(asctime)s.%(msecs)03d [%(name)s] %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S', style='%')
log_stderr = logging.StreamHandler()
log_stderr.setFormatter(log_formatter)


__author__ = 'dj4ck@darc.de'
__version__ = '20210404'

HELP = {
        'quit':"q[uit]  program",
        'add': "a[dd]   talkgroup",
        'del': "d[el]   [talkgroup]",
        'help':"h[elp]  print this help",
}


class SimpleCompleter:
    """
    used with readline
    """
    def __init__(self, options):
        self.options = sorted(options)
    def complete(self, text, state):
        response = None
        if state == 0:
            if text:
                self.matches = [s for s in self.options if s and s.startswith(text)]
            else:
                self.matches = self.options[:]
        try:
            response = self.matches[state]
        except IndexError:
            response = None
        return response


class AudioSink():
    """
    plays audio
    """
    def __init__(self, speaker, name="audio"):
        self.sink = speaker
        self.latency = '500'
        device_option = [] if speaker=='default' else ["--device", speaker]

        self.audio_play_cmd = [
                "pacat",
                "-p",
                "--latency-msec", self.latency,
                "--rate", "8000",
                "--format", "s16be",
                "--channels", "1",
                "--stream-name", name,
        ] + device_option

        self.audio_player = None
        self.handle = None

    def start(self):
        """
        return filehandle for pcm input
        """
        self.audio_player = subprocess.Popen(self.audio_play_cmd, stdin=subprocess.PIPE)
        self.handle = self.audio_player.stdin
        return self.handle

    def stop(self):
        self.audio_player.terminate()
        self.audio_player.wait()


class DVstick30():
    """
    dvmega with AMBE3000R codec
    """
    def __init__(self, device='/dev/ttyUSB0', baudrate=460800):
        self._device_name = device
        self._baudrate = baudrate
        self._MODEL = 'AMBE3000R'
        self.buffer = b''
        self._start_byte = b'\x61'
        self._TYPE_PCM = 0x2
        self._TYPE_AMBE = 0x1
        self._TYPE_CTRL = 0x0
        self._type = { 'cfg':b'\x00', 'speech':b'\x02','channel':b'\x01' }

        self.log = logging.getLogger('dv30')
        self.log.addHandler(log_stderr)
        self.log.setLevel(logging.INFO)

        self._device = serial.Serial(self._device_name, baudrate=self._baudrate, timeout=1)

    def _packet(self, packet_type, payload):
        packet = self._start_byte + (len(payload)).to_bytes(2,'big') + packet_type + payload
        return packet

    def set_dmr_mode(self):
        self._set_rate_table(33)  # set DMR mode
        return self.read_answer()

    @property
    def handle(self):
        return self._device

    def close(self):
        if self._device.isOpen():
            self._device.close()

    def read_answer(self, full_frame=False, max=0):
        try:
            header = self._device.read(4)
            length_of_answer = int.from_bytes(header[1:-1], byteorder='big')
            if max > 0:
                if length_of_answer > max:
                    return "ERROR:reading!"
            data = self._device.read(length_of_answer)
            if full_frame:
                return header + data
        except:
            data = "ERROR:reading!"
        return data


    def model(self):
        self._device.write(b'\x61\x00\x01\x00\x30')
        try:
            m = self.read_answer(max=30)[1:-1].decode()
        except:
            m = "Error: model!"
        return m

    def version(self):
        self._device.write(b'\x61\x00\x01\x00\x31')
        return self.read_answer()[1:-1].decode()

    def codec_ok(self):
        self._device.reset_input_buffer()
        self._device.reset_output_buffer()
        model = self.model()
        if model == self._MODEL:
            return True
        return False

    def _set_rate_table(self, table_index=33):
        """
        set ambe rate via table (table_index[33] = DMR)
        """
        msg = self._packet(packet_type=self._type['cfg'], payload=b'\x09'+table_index.to_bytes(1,'big'))
        self._device.write(msg)

    def pcm2ambe_write(self, raw_pcm):
        """
        writes pcm to codec
        async IO
        """
        if len(raw_pcm) != 320:
            self.log.error("pcm2ambe: Wrong raw_pcm length {:}!".format(len(raw_pcm)))
        packet = self._packet(self._type['speech'], b'\x00\xa0' + raw_pcm)
        self._device.write(packet)

    def ambe2pcm_write(self, raw_ambe):
        if len(raw_ambe) != 9:
            self.log.error("ambe2pcm_write: Wrong raw_ambe length {:}!".format(len(raw_ambe)))
        packet = self._packet(self._type['channel'], b'\x01\x48' + raw_ambe)
        self._device.write(packet)

    def read_data(self):
        """
            0       1 2    3   4:4+N    4+N:...
        start_byte length type payload  [index]
            |        |     |   '------- [4:4+N]  N bytes
            |        |     '-----------   [3]    1 byte
            |        '----------------- [1:3]    2 bytes N
            '--------------------------   [0]    1 byte  0x61
        """
        Packets = []
        response = self._device.read_all()
        self.buffer += response
        while self.buffer:
            try:
                # get index of first _start_byte in buffer
                idx = self.buffer.index(self._start_byte)
            except ValueError:
                break
            if len(self.buffer[idx:]) < 4:
                break
            packet_type = self.buffer[idx+3]
            packet_len = int.from_bytes(self.buffer[idx+1:idx+3], 'big')
            if len(self.buffer[idx:]) < packet_len + 4:
                break
            if packet_type in (self._TYPE_PCM, self._TYPE_AMBE):
                #       p a y l o a d
                #   [0]      [1]   [2:] 
                # field_id number payload_data
                # 1_byte   1_byte   N_bytes
                data_type = self.buffer[idx+4]
                payload = self.buffer[idx+6:idx+packet_len+4]
                Packets.append(('pcm' if data_type == 0 else 'ambe', payload))
                self.buffer = self.buffer[idx+packet_len+4:]
            elif packet_type == self._TYPE_CTRL:
                answer, payload = self.buffer[idx+4], self.buffer[idx+5:idx+packet_len+2]
                Packets.append(('ctrl', answer, payload))
                self.buffer = self.buffer[idx+packet_len+4:]
            else:
                self.log.error("unknown packet type: {:}".format(packet_type))
                self.buffer = self.buffer[idx+1:]
        return Packets




class OTPConstants():
    """
    Open DMR Terminal Protocol Constants
    """
    REWIND_PROTOCOL_SIGN        = b'REWIND01'
    REWIND_SIGN_LENGTH          = len(REWIND_PROTOCOL_SIGN)

    REWIND_CLASS_REWIND_CONTROL = 0x0000
    REWIND_CLASS_SYSTEM_CONSOLE = 0x0100
    REWIND_CLASS_SERVER_NOTICE  = 0x0200
    REWIND_CLASS_DEVICE_DATA    = 0x0800
    REWIND_CLASS_APPLICATION    = 0x0900
    REWIND_CLASS_TERMINAL       = 0x0a00

    REWIND_TYPE_KEEP_ALIVE      = 0x0
    REWIND_TYPE_CLOSE           = 0x1
    REWIND_TYPE_CHALLENGE       = 0x2
    REWIND_TYPE_AUTHENTICATION  = 0x3

    REWIND_TYPE_REDIRECTION = 0x8
    REWIND_TYPE_REPORT      = 0x0100

    REWIND_TYPE_BUSY_NOTICE     = 0x0200
    REWIND_TYPE_ADDRESS_NOTICE  = 0x0201
    REWIND_TYPE_BINDING_NOTICE  = 0x0202

    REWIND_TYPE_CONFIGURATION       = 0x0900
    REWIND_TYPE_SUBSCRIPTION        = 0x0901
    REWIND_TYPE_CANCELLING          = 0x0902
    REWIND_TYPE_SESSION_POLL        = 0x0903
    REWIND_TYPE_DMR_DATA_BASE       = 0x0910    # RT sequence counter
    REWIND_TYPE_HEADER_WITH_FLC     = 0x0911    # RT sequence counter
    REWIND_TYPE_TERMINATOR_WITH_FLC = 0x0912    # RT sequence counter
    REWIND_TYPE_DMR_AUDIO_FRAME     = 0x0920    # RT sequence counter
    REWIND_TYPE_DMR_EMBEDDED_DATA   = 0x0927
    REWIND_TYPE_SUPER_HEADER        = 0x0928
    REWIND_TYPE_FAILURE_CODE        = 0x0929

    REWIND_TYPE_TERMINAL_IDLE       = 0x0a00
    REWIND_TYPE_TERMINAL_ATTACH     = 0x0a02
    REWIND_TYPE_TERMINAL_DETACH     = 0x0a03
    REWIND_TYPE_MESSAGE_TEXT        = 0x0a10
    REWIND_TYPE_MESSAGE_STATUS      = 0x0a11
    REWIND_TYPE_LOCATION_REPORT     = 0x0a20
    REWIND_TYPE_LOCATION_REQUEST    = 0x0a21

    REWIND_FLAG_NONE        = 0x00
    REWIND_FLAG_REAL_TIME_1 = 0x01
    REWIND_FLAG_REAL_TIME_2 = 0x02
    REWIND_FLAG_BUFFERING   = 0x04
    REWIND_FLAG_DEFAULT_SET = 0x00

    REWIND_ROLE_REPEATER_AGENT  = 0x10
    REWIND_ROLE_APPLICATION     = 0x20

    REWIND_SERVICE_CRONOS_AGENT         = 0x10  # 1 byte
    REWIND_SERVICE_TELLUS_AGENT         = 0x11  # 1 byte
    REWIND_SERVICE_SIMPLE_APPLICATION   = 0x20  # 1 byte
    REWIND_SERVICE_OPEN_TERMINAL        = 0x21  # 1 byte

    REWIND_OPTION_SUPER_HEADER  = 0x01
    REWIND_OPTION_LINEAR_FRAME  = 0x02

    REWIND_CALL_LENGTH  = 10

class OpenTerminalProtocol(OTPConstants):
    """
    ----------------
    Message stucture
    ----------------

    REWIND01 tt ff ssss ll payload
        |     |  |   |   | '------ n bytes payload
        |     |  |   |   '-------- 2 bytes length of payload (n)
        |     |  |   '------------ 4 bytes sequence number
        |     |  '---------------- 2 bytes flags
        |     '------------------- 2 bytes type
        '--------------------------8 bytes protocol sign
                     
    """
    def __init__(self):
        self._seq_num = -1      # normal sequence counter
        self._seq_num_rt = -1   # realtime sequence counter
        self._description = "pySPOT {:}".format(__version__).encode()
        self._msg = b''
        self._token = b''
        self.msg_type = -1
        self.msg_flags = -1
        self.msg_seq = -1
        self.msg_payload_length = -1
        self.msg_payload = b''

    def init_user(self, user_id, terminal_id, password):
        self.user_id = user_id  # used by pyspot tx task
        self.terminal_id = terminal_id.to_bytes(4,'little')
        self._password = password.encode() if type(password) is str else password

    def set_msg(self, msg):
        """
        set message
        """
        self._msg = msg
        self.msg_type = int.from_bytes(self._msg[self.REWIND_SIGN_LENGTH:self.REWIND_SIGN_LENGTH+2], 'little')
        self.msg_flags = int.from_bytes(self._msg[self.REWIND_SIGN_LENGTH+2:self.REWIND_SIGN_LENGTH+4], 'little')
        self.msg_seq = int.from_bytes(self._msg[self.REWIND_SIGN_LENGTH+4:self.REWIND_SIGN_LENGTH+8], 'little')
        self.msg_payload_length = int.from_bytes(self._msg[self.REWIND_SIGN_LENGTH+8:self.REWIND_SIGN_LENGTH+10], 'little')
        self.msg_payload = self._msg[self.REWIND_SIGN_LENGTH+10:]

    def decode_flc(self):
        if self.msg_type in (self.REWIND_TYPE_HEADER_WITH_FLC, self.REWIND_TYPE_TERMINATOR_WITH_FLC):
            return self.msg_payload[0], \
                    self.msg_payload[1], \
                    self.msg_payload[2], \
                    int.from_bytes(self.msg_payload[3:6],'big'), \
                    int.from_bytes(self.msg_payload[6:9], 'big')
        return None, None, None, None, None

    def encode_flc(self, dst, src, private=False):
        flc = b'\x03' if private else b'\x00'
        flc += b'\x00\x04'
        if src > 9999999: src = int(str(src)[:7])   # allow user dmrid suffix 00-99
        flc += dst.to_bytes(3,'big') + src.to_bytes(3,'big') + b'\x00\x00\x00'
        return flc

    def _frame(self, frame_type, flags, seq_num, payload=b''):
        """
        build open terminal frame
        """
        return self.REWIND_PROTOCOL_SIGN + \
                frame_type.to_bytes(2,'little') + \
                flags.to_bytes(2,'little') + \
                seq_num.to_bytes(4,'little') + \
                len(payload).to_bytes(2,'little') + \
                payload

    def set_token(self):
        """
        use only if self._msg is loaded with REWIND_TYPE_CHALLENGE message
        """
        self._token = self._msg[self.REWIND_SIGN_LENGTH+10:]
        return self._token 

    def keep_alive_frame(self):
        self._seq_num = (self._seq_num + 1) % 0xffffffff
        payload = self.terminal_id + self.REWIND_SERVICE_OPEN_TERMINAL.to_bytes(1,'little') + self._description
        return self._frame(self.REWIND_TYPE_KEEP_ALIVE, self.REWIND_FLAG_NONE, self._seq_num, payload)

    def authentication_frame(self, token=None):
        self._seq_num = (self._seq_num + 1) % 0xffffffff
        m = hashlib.sha256()
        token = self._token if token is None else token
        m.update(token)
        m.update(self._password)
        payload = m.digest()
        return self._frame(self.REWIND_TYPE_AUTHENTICATION, self.REWIND_FLAG_NONE, self._seq_num, payload)

    def subscribe_frame(self, talkgroup, private=False):
        self._seq_num = (self._seq_num + 1) % 0xffffffff
        payload = (5).to_bytes(4,'little') if private else (7).to_bytes(4,'little')
        payload += talkgroup.to_bytes(4,'little')
        return self._frame(self.REWIND_TYPE_SUBSCRIPTION, self.REWIND_FLAG_NONE, self._seq_num, payload)

    def unsubscribe_frame(self, talkgroup=None, private=False):
        self._seq_num = (self._seq_num + 1) % 0xffffffff
        if talkgroup is None:
            payload = b''
        else:
            payload = (5).to_bytes(4,'little') if private else (7).to_bytes(4,'little')
            payload += talkgroup.to_bytes(4,'little')
        return self._frame(self.REWIND_TYPE_CANCELLING, self.REWIND_FLAG_NONE, self._seq_num, payload)

    def dmr_audio_header_frame(self, dst, src, private=False):
        self._seq_num_rt = (self._seq_num_rt + 1) % 0xffffffff
        flc = self.encode_flc(dst, src, private)
        return self._frame(self.REWIND_TYPE_HEADER_WITH_FLC, self.REWIND_FLAG_REAL_TIME_1, self._seq_num_rt, flc)

    def dmr_audio_data_frame(self, ambe):
        self._seq_num_rt = (self._seq_num_rt + 1) % 0xffffffff
        return self._frame(self.REWIND_TYPE_DMR_AUDIO_FRAME, self.REWIND_FLAG_REAL_TIME_1, self._seq_num_rt, ambe)

    def dmr_audio_terminator_frame(self, dst, src, private=False):
        self._seq_num_rt = (self._seq_num_rt + 1) % 0xffffffff
        flc = self.encode_flc(dst, src, private)
        return self._frame(self.REWIND_TYPE_TERMINATOR_WITH_FLC, self.REWIND_FLAG_REAL_TIME_1, self._seq_num_rt, flc)

    def close_frame(self):
        self._seq_num = (self._seq_num + 1) % 0xffffffff
        return self._frame(self.REWIND_TYPE_CLOSE, self.REWIND_FLAG_NONE, self._seq_num)



class OTCF():
    """
    Open Terminal Client Factory (asyncio)
        used to connect to BrandMeister master server
    """
    def __init__(self, user_id, terminal_id, password, dv30=None, logger=None):
        self.p = OpenTerminalProtocol()
        self.dv30 = dv30
        self.p.init_user(user_id, terminal_id, password)
        self.subscriptions = []
        self.log = logger
        self.last_keep_alive_ack = time()
        self._keep_alive_interval = 5   # seconds
        self._header_seq = -1   # avoid multiple header logs
        self.loop = asyncio.get_running_loop()
        self._reconnect_in = 20 # seconds
        self.FUT_CONNECTED = self.loop.create_future()
        self._prompt_length = 0
        self.header_epoch = datetime.now()

    def prompt(self, message=""):
        t = "{:} {:} ({:})> ".format(message, self.p.user_id, ",".join([str(s) for s in self.subscriptions])) if self.subscriptions else "{:} {:} (-)> ".format(message, self.p.user_id)
        return t.lstrip()
    

    def connection_made(self, transport):
        """
        send keep alive message on connection to request rewind_type_challenge message
        """
        self.transport = transport
        #
        # connect
        self.sendto_server(self.p.keep_alive_frame())
        self.log.info("Open Terminal Protocol Factory started, try to connect...")
        self.keep_alive_task = self.loop.create_task(self.keep_alive_loop())

    def sendto_server(self, message, log=False):
        self.transport.sendto(message)
        if log:
            self.log.info("sent {:} to brandmeister".format(message))


    def datagram_received(self, data, addr):
        """
        process received messages from BrandMeister
        """
        if not data.startswith(self.p.REWIND_PROTOCOL_SIGN) or len(data) < (self.p.REWIND_SIGN_LENGTH)+10:
            self.log.error("got bogus data {:}, from {:} packet dismissed!".format(data, addr))
            return
        self.p.set_msg(data)

        if self.p.msg_type == self.p.REWIND_TYPE_DMR_AUDIO_FRAME:
            #
            # got AMBE data, send to voice codec
            if len(self.p.msg_payload) == 27:
                Chunks = [ self.p.msg_payload[i:i+9] for i in range(0,27,9) ]
                for chunk in Chunks:
                    self.dv30.ambe2pcm_write(chunk)

        elif self.p.msg_type == self.p.REWIND_TYPE_CHALLENGE:
            #
            # got challenge, set token, answer with auth
            token = self.p.set_token()
            if len(token) == 4:
                self.sendto_server(self.p.authentication_frame())
            else:
                self.log.error("Invalid token '{:}' received, login failed!".format(token))

        elif self.p.msg_type == self.p.REWIND_TYPE_KEEP_ALIVE:
            #
            # got keep alive acknowledge
            self.last_keep_alive_ack = time()
            if not self.FUT_CONNECTED.done():
                    #
                    # first connected, auth accepted
                    self.log.info("BrandMeister LOGIN ACCEPTED.")
                    self.FUT_CONNECTED.set_result(True)

        elif self.p.msg_type == self.p.REWIND_TYPE_SUBSCRIPTION:
            #
            # got subscription acknowledge
            try:
                self.fut_add_tg.set_result(True)
            except Exception as e:
                self.log.error("got unexpected subscription acknowledge {:}!".format(e))

        elif self.p.msg_type == self.p.REWIND_TYPE_HEADER_WITH_FLC:
            byte1, feature, service, dst, src = self.p.decode_flc()
            if abs(self.p.msg_seq - self._header_seq) > 1:
                self.log.info("CALL {:} <- {:}".format(dst, src))
                self.header_epoch = datetime.now()
            self._header_seq = self.p.msg_seq


        elif self.p.msg_type == self.p.REWIND_TYPE_TERMINATOR_WITH_FLC:
            byte1, feature, service, dst, src = self.p.decode_flc()
            self.log.info(" END {:} <- {:} ({:})".format(dst, src, str(datetime.now()-self.header_epoch)[:-5]))

        elif self.p.msg_type == self.p.REWIND_TYPE_DMR_EMBEDDED_DATA:
            pass

        elif self.p.msg_type == self.p.REWIND_TYPE_CANCELLING:
            #
            # got ack unsubscribe
            try:
                self.fut_del_tg.set_result(True)
                self.log.debug("Delete talkgroup accepted.")
            except Exception as e:
                self.log.error("got unexpected delete acknowledge {:}!".format(e))
        else:
            self.log.warning("Got unhandled msg_type:{:} flags:{:} msg: {:}".format(hex(self.p.msg_type), hex(self.p.msg_flags), self.p._msg))

    def error_received(self, exc):
        """
        set ERROR true on error and status ''
        """
        if self.FUT_CONNECTED.done():
            self.log.error("error_received: {:}".format(exc))
            self.FUT_CONNECTED = self.loop.create_future()

    def connection_lost(self, exc):
        """
        set ERROR true on connection lost and status ''
        """
        self.log.error("connection_lost: {:}".format(exc))

    async def add_tg(self, tg):
        self.fut_add_tg = self.loop.create_future()
        if not self.FUT_CONNECTED.done():
            self.log.info("waiting on connection auth...")
            try:
                await asyncio.wait_for(self.FUT_CONNECTED, timeout=3.0)
            except asyncio.TimeoutError:
                self.log.error("timeout in add_tg, waiting on connection.")
                return False
            except Exception as e:
                self.log.error("add_tg exception: {:}".format(e))
                return False

        if not tg in self.subscriptions:
            self.sendto_server(self.p.subscribe_frame(tg))
            try:
                tg_added = await asyncio.wait_for(self.fut_add_tg, timeout=0.5)
                if tg_added:
                    self.log.info("talkgroup({:}) added.".format(tg))
                    self.subscriptions.append(tg)
                    return tg_added
            except asyncio.TimeoutError:
                self.log.info("timeout add_tg({:}), try again...".format(tg))
            except Exception as e:
                self.log.error("{:}: in add_tg".format(e))
        else:
            self.log.warning("TG {:} already subscribed!".format(tg))
        return False

    async def del_tg(self, tg=None):
        self.fut_del_tg = self.loop.create_future()
        if not self.FUT_CONNECTED.done():
            try:
                await asyncio.wait_for(self.FUT_CONNECTED, timeout=0.5)
            except asyncio.TimeoutError:
                self.log.error("timeout in del_tg, waiting on connection.")
                return False
            except Exception as e:
                self.log.error("del_tg exception: {:}".format(e))
                return False
        if tg is None or tg in self.subscriptions:
            self.sendto_server(self.p.unsubscribe_frame(tg))
            try:
                tg_deleted = await asyncio.wait_for(self.fut_del_tg, timeout=0.5)
                if tg_deleted:
                    log_msg = "talkgroup(all) deleted." if tg is None else "talkgroup({:}) deleted.".format(tg)
                    self.log.info(log_msg)
                    if tg is None:
                        self.subscriptions = []
                    else:
                        self.subscriptions.remove(tg)
                    return tg_deleted
            except asyncio.TimeoutError:
                self.log.info("timeout del_tg({:}), try again...".format(tg))
            except Exception as e:
                self.log.error("{:}: in del_tg".format(e))
        else:
            self.log.warning("TG {:} not subscribed!".format(tg))
        return False


    async def keep_alive_loop(self):
        """
        sends keep_alive messages periodically
        tiggers reconnect on missing keep_alive_ack
        """
        self.log.info("Keep alive loop started.")
        reconnect_counter = 0
        while True:
            await asyncio.sleep(self._keep_alive_interval)
            if self.FUT_CONNECTED.done():
                self.sendto_server(self.p.keep_alive_frame())
                if (time() - self.last_keep_alive_ack) > self._keep_alive_interval*3:
                    self.log.warning("missing keep alive ack, set: CONNECTED = False!")
                    self.sendto_server(self.p.close_frame())
                    self.FUT_CONNECTED = self.loop.create_future()
                    reconnect_counter += 1
            else:
                if reconnect_counter > 3:
                    self.log.info("try to reconnect...")
                    self.sendto_server(self.p.keep_alive_frame())
                    reconnect_counter = 0
                else:
                    reconnect_counter += 1


def cmd_loop(cmd_sock):
    """
    read user commands from STDIN, forwards input to worker loop via socketpair
    """

    cmd_sock.settimeout(5)  # wait max. 5 seconds on command response

    while True:
        try:
            prompt = cmd_sock.recv(1024)
            prompt = pickle.loads(prompt)
        except:
            prompt = "timeout> "
        command = input(prompt)
        cmd, *parameter = split('[=|,| |;|-]+', command)

        if cmd in ("q", "quit"):
            # terminate program
            C = pickle.dumps({'quit':True})
            cmd_sock.sendall(C)
            break

        elif cmd in ("d", "del"):
            # unsubscribe from tg...
            tg = None
            try:
                tg = int(parameter[0])
            except:
                pass
            C = pickle.dumps({'del':{'tg':tg}})
            cmd_sock.sendall(C)

        elif cmd in ("a", "add"):
            # add talkgroup
            try:
                tg = parameter[0]
                tg = int(tg)
                C = pickle.dumps({'add':tg})
                cmd_sock.sendall(C)
            except Exception as e:
                C = pickle.dumps({'error':e})
                cmd_sock.sendall(C)
 
        elif cmd in ("h", "help"):
            # print help
            C = pickle.dumps({'help':''})
            cmd_sock.sendall(C)

        else:
            C = pickle.dumps({'unknown':"{:}".format(cmd)})
            cmd_sock.sendall(C)


async def work_loop(user_sock, user_queue, oterm, dv30, HELP, log):
    """
    waits for user commands and evaluates
    """
    # send first prompt to user
    user_sock.sendall(pickle.dumps(oterm.prompt()))

    while True:
        #
        # use Queue!! not socket direct to avoid blocking!!
        message = await user_queue.get()
        error = ""
        if 'add' in message:
            tg = message['add']
            ack = await oterm.add_tg(tg)

        elif 'del' in message:
            tg = message['del']['tg']
            ack = await oterm.del_tg(tg)

        elif 'quit' in message:
            log.info("send close_frame to bm-master")
            oterm.sendto_server(oterm.p.close_frame())
            break

        elif 'help' in message:
            for top in HELP:
                print("\t{:},\t{:}".format(top, HELP[top]), flush=True)
        elif 'error' in message:
            log.warning("user input: {:}".format(message['error']))
        else:
            log.warning("got unknown command: {:}".format(message))

        # send confirmation to user input via socketpair
        user_sock.sendall(pickle.dumps(oterm.prompt(error)))
    return


class UserCommandListener:
    """
    * listen on socketpair for user commands
    * forwards user input via socket to queue (work_loop)
    * this avoids blocking!
    """
    def __init__(self, queue):
        self.queue = queue
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        """
        got user message via unix socket
        """
        message = pickle.loads(data)
        self.queue.put_nowait(message)

    def connection_lost(self, exc):
        pass

    def eof_received(self):
        pass


def pcm_to_speaker(dv30, speaker):
    """
    read pcm data from codec, write pcm to speaker
    """
    Packets = dv30.read_data()
    for packet in Packets:
        data_type, data = packet
        if data_type == 'pcm':
            speaker.write(data)



async def main():
    """
    * Brandmeister DMR Open Terminal Client
    """
    loop = asyncio.get_running_loop()

    #
    # options
    parser = argparse.ArgumentParser(description="Asyncio DMR Open Terminal RX-Client (DJ4CK)", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-c", dest="config", type=str, help="configuration file", action="store", required=True)
    parser.add_argument("-l", dest="log_file", type=str, help="log file", action="store")
    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + "version '{:}', by {:}".format(__version__, __author__))
    options = parser.parse_args()

    #
    # setup logging
    log = logging.getLogger('main')
    if options.log_file:
        log_fh = logging.FileHandler(filename=options.log_file)
        log_fh.setFormatter(log_formatter)
        log.addHandler(log_fh)
    else:
        log.addHandler(log_stderr)
    log.setLevel(logging.INFO)

    # Register my completer function
    readline.set_auto_history(True)
    readline.set_completer(SimpleCompleter(list(HELP.keys())).complete)
    # Use the tab key for completion
    readline.parse_and_bind('tab: complete')

    #
    # read config
    cfg = configparser.ConfigParser(comment_prefixes=('#',';'), inline_comment_prefixes=('#'))
    cfg.read(options.config)

    #
    # check for pacat program
    if find_executable('pacat') is None:
        exit("Can't find pulseaudio 'pacat' program -> EXIT !!")

    #
    # start audio play
    speaker = cfg["audio"]["speaker"]
    pulse_player = AudioSink(speaker, "pyspot_rx")
    speaker = pulse_player.start()

    #
    # queues
    user_queue = asyncio.Queue()        # filled by UserCommandListener

    #
    # socket pair for user command <-> work loop communication
    cmd_sock, work_sock = socket.socketpair(type=socket.SOCK_STREAM)

    #
    # Register the work socket to wait and forward data (NECESSARY to avoid blocking sock.recv())
    ucl_transport, ucl_protocol = await loop.create_connection(
            lambda: UserCommandListener(user_queue),
            sock=work_sock
    )

    #
    # setup ambe voco
    dv30 = DVstick30(cfg.get('dv30','device'))
    if not dv30.codec_ok():
        exit("DVstick30 problem!")
    dv30.set_dmr_mode()

    #
    # add dv30 reader
    loop.add_reader(dv30.handle, pcm_to_speaker, dv30, speaker)
    log.info("dv30 reader started.")

    #
    # connect to BrandMeister Server
    oterm_transport, oterm_protocol = await loop.create_datagram_endpoint(lambda: OTCF(
        user_id=cfg.getint('pyspot_rx', 'user_id'),
        terminal_id=cfg.getint('master','terminal_id'),
        password=cfg['master']['password'],
        dv30=dv30,
        logger=log,
        ), remote_addr=(cfg['master']['ip'], cfg.getint('master', 'port'))
    )

    #
    # start working loop (user command executor)
    work_task = loop.create_task(work_loop(work_sock, user_queue, oterm_protocol, dv30, HELP, log))

    #
    # run command loop until user terminates
    await loop.run_in_executor(None, cmd_loop, cmd_sock)

    #
    # wait until work_task terminates
    await work_task

if __name__ == '__main__':
    asyncio.run(main())

