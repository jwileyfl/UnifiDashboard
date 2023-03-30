import os
import unificontrol
import dash
from dash import dcc
from dash import html
from dash.dependencies import Input
from dash.dependencies import Output
import plotly
#import plotly.express as px
import pandas as pd
import time
import logging
import socket
import getpass
import cryptography.fernet

unifiHostName: str = ''
unifiPort: int = 0
unifiUserName: str = ''
unifiPW: str = ''

appConf: dict = {}
logger: logging.Logger
key: bytes
keyFile: str = os.path.join(os.getenv('HOMEDRIVE'), os.getenv('HOMEPATH'), 'unifiDashboard.key')
configFile: str = 'unifiDashboard.cfg'
controller: unificontrol.UnifiClient  # = unificontrol.UnifiClient(unifiHostName, unifiPort, unifiUserName, unifiPW)
systemInfo: dict = {'Type': '', 'Name': '', 'Hostname': '', 'Ip': [], 'Version': '', 'Update': False, 'PkgVersion': '', 'PkgUpdate': False}
signal_counts: dict = {'Poor': 0, 'Moderate': 0, 'Good': 0, 'Excellent': 0}
userList: list = []
clients = None # controller.list_clients()
clientList: list = []
wiredCount: int = 0
wirelessCount: int = 0
uniqueWifiList: list = []
uniqueWifiCountList: list = []
tmpWifi: list = []
mediaPie: plotly.graph_objects.Figure
wifiPie: plotly.graph_objects.Figure
signalPie: plotly.graph_objects.Figure
systemTable: plotly.graph_objects.Figure
clientTable: plotly.graph_objects.Figure


def init_logger():
    global logger

    logger = logging.getLogger("mainLogger")
    logger.setLevel(logging.DEBUG)
    loggerHandler = logging.FileHandler('UnifiDashboard.log')
    logFormatter = logging.Formatter('%(asctime)s %(levelname)s - %(message)s')
    loggerHandler.setFormatter(logFormatter)
    logger.addHandler(loggerHandler)


def fileExists(fileName: str):
    return os.path.exists(fileName)


def create_config_dict(host: str, port: int, u: str, p: str):
    config_dict = {
        'server': {
            'hostname': host,
            'port': port
        },
        'credentials': {
            'username': u,
            'password': p
        }
    }

    return config_dict


def create_config_file(config: dict, fileName: str):
    configuration = open(fileName, 'w')

    for section, options in config.items():
        configuration.write(f'[{section}]\n')
        for option, value in options.items():
            configuration.write(f'{option} = {value}\n')
        configuration.write('\n')

    configuration.close()


def read_config_file(configFile: str):
    config_data: dict = {}

    configuration = open(configFile, 'r')
    section = None

    for line in configuration:
        line = line.strip()
        if line.startswith('[') and line.endswith(']'):
            #section
            section = line.replace('[', '', 1).replace(']','', 1)
            #section = line[1:-1]
            config_data[section] = {}
        elif section is not None and '=' in line:
            option, value = line.split('=', 1)
            config_data[section][option.strip()] = value.strip()
    
    configuration.close()

    return config_data


def get_stored_server_config(config: dict):
    hostName: str = ''
    port: int = 0

    hostName = config['server']['hostname']
    port = config['server']['port']

    return hostName, port


def get_stored_credentials(config: dict):
    userName: str = ''
    password: str = ''

    userName = config['credentials']['username']
    password = config['credentials']['password']

    return userName, password


def get_config_from_user():
    print('Enter Unifi server info')
    hostName: str = input('HostName: ')
    port: int = int(input('Port: '))
    print('Unifi User credentials needed to continue')
    userName: str = input('User Name: ')
    password: str = getpass.getpass('Password: ')

    return hostName, port, userName, password


def generate_key():
    return cryptography.fernet.Fernet.generate_key()
    

def store_key(key: bytes, file: str):
    if os.path.exists(file):
        os.chmod(file, 666) #read/write

    f = open(file, 'w')
    f.write(key.decode('utf-8'))
    f.close()
    os.chmod(file, 444) #read only


def get_key(file: str):
    f = open(file, 'r')
    for line in f:
        return line.encode('utf-8')
    

def encrypt_credentials(userName: str, password: str, key: bytes):
    encrypted_userName: str = cryptography.fernet.Fernet(key).encrypt(userName.encode('utf-8')).decode('utf-8')
    encrypted_password: str = cryptography.fernet.Fernet(key).encrypt(password.encode('utf-8')).decode('utf-8')
    return encrypted_userName, encrypted_password


def decrypt_credentials(encryptedUserName: str, encryptedPassword: str, key: bytes):
    userName: str = cryptography.fernet.Fernet(key).decrypt(encryptedUserName.encode('utf-8')).decode('utf-8')
    password: str = cryptography.fernet.Fernet(key).decrypt(encryptedPassword.encode('utf-8')).decode('utf-8')
    return userName, password


def init_controller():
    logger.debug('init_controller()')
    return unificontrol.UnifiClient(unifiHostName, unifiPort, unifiUserName, unifiPW)


def fetch_system_info():
    logger.debug('fetch_system_info()')
    tmpType: str = ''
    tmpName: str = ''
    tmpHost: str = ''
    tmpIp: list = []
    tmpVer: str = ''
    tmpUpd: bool = False
    tmpPkgVer: str = ''
    tmpPkgUpd: bool = False
    tmpInfo = controller.stat_sysinfo()

    for si in tmpInfo:

        if 'ubnt_device_type' in si:
            if si['ubnt_device_type'] is not None:
                tmpType = si['ubnt_device_type']

        if 'name' in si:
            if si['name'] is not None:
                tmpName = si['name']

        if 'hostname' in si:
            if si['hostname'] is not None:
                tmpHost = si['hostname']

        if 'ip_addrs' in si:
            if si['ip_addrs'] is not None:
                ips = si['ip_addrs']
                for ip in ips:
                    tmpIp.append(ip)

        if 'version' in si:
            if si['version'] is not None:
                tmpVer = si['version']

        if 'update_available' in si:
            if si['update_available'] == True:
                tmpUpd = True

        if 'package_version' in si:
            if si['package_version'] is not None:
                tmpPkgVer = si['package_version']

        if 'package_update_available' in si:
            if si['package_update_available'] == True:
                tmpPkgUpd = True

    return { 'Type': tmpType, 'Name': tmpName, 'Hostname': tmpHost, 'Ip': tmpIp, 'Version': tmpVer, 'Update': tmpUpd, 'PkgVersion': tmpPkgVer, 'PkgUpdate': tmpPkgUpd }


def fetch_users():
    logger.debug('fetch_users()')
    return controller.list_users()


def fetch_static_data():
    global userList, systemInfo
    logger.debug('fetch_static_data()')

    userList = fetch_users()
    systemInfo = fetch_system_info()


def fetch_client_data():
    logger.debug('fetch_data()')
    global tmpWifi, wiredCount, wirelessCount, uniqueWifiList, uniqueWifiCountList, clientList, signal_counts

    tmpName: list = []
    tmpHost: list = []
    tmpMan: list = []
    tmpMac: list = []
    tmpResIp: list = []
    tmpIp: list = []
    tmpMedia: list = []
    tmpNote: list = []
    tmpWifi = []
    wiredCount = 0
    wirelessCount = 0
    uniqueWifiList = []
    uniqueWifiCountList = []
    clientList = []
    signal_counts = {'Poor': 0, 'Moderate': 0, 'Good': 0, 'Excellent': 0}

    clients = controller.list_clients()

    for cl in clients:
        if 'name' in cl:
            tmpName.append(cl['name'])
        else:
            tmpName.append('')

    clientList.append(tmpName)

    for cl in clients:
        if 'hostname' in cl:
            tmpHost.append(cl['hostname'])
        else:
            tmpHost.append('')

    clientList.append(tmpHost)

    for cl in clients:
        if 'oui' in cl:
            tmpMan.append(cl['oui'])
        else:
            tmpMan.append('')

    clientList.append(tmpMan)

    for cl in clients:
        if 'mac' in cl:
            tmpMac.append(cl['mac'])
        else:
            tmpMac.append('')

    clientList.append(tmpMac)

    for cl in clients:
        if 'use_fixedip' in cl:
            if cl['use_fixedip'] == True:
                if 'fixed_ip' in cl:
                    tmpResIp.append(cl['fixed_ip'])
                else:
                    tmpResIp.append('')
            else:
                tmpResIp.append('')
        else:
            tmpResIp.append('')

    clientList.append(tmpResIp)

    for cl in clients:
        if 'ip' in cl:
            if cl['ip'] is not None:
                tmpIp.append(cl['ip'])
            else:
                tmpIp.append('')
        else:
            tmpIp.append('')

    clientList.append(tmpIp)

    for cl in clients:
        if 'is_wired' in cl:
            if cl['is_wired'] == True:
                tmpMedia.append('Wired')
                wiredCount += 1
            else:
                tmpMedia.append('Wireless')
                wirelessCount += 1
        else:
            tmpMedia.append('Wireless')
            wirelessCount += 1

        if 'signal' in cl:
            signal = cl['signal'] or 0
            if signal < -80:
                signal_counts['Poor'] += 1
            elif signal < -70:
                signal_counts['Moderate'] += 1
            elif signal < -60:
                signal_counts['Good'] += 1
            else:
                signal_counts['Excellent'] += 1

    clientList.append(tmpMedia)

    for cl in clients:
        if 'essid' in cl:
            tmpWifi.append(cl['essid'])
        else:
            tmpWifi.append('')

    uniqueWifiList = (list(set(tmpWifi)))
    uniqueWifiList.remove('')
    for uW in uniqueWifiList:
        uniqueWifiCountList.append(tmpWifi.count(uW))

    clientList.append(tmpWifi)

    for cl in clients:
        if 'noted' in cl:
            if cl['noted'] == True:
                if 'note' in cl:
                    tmpNote.append(cl['note'])
                else:
                    tmpNote.append('')
            else:
                tmpNote.append('')
        else:
            tmpNote.append('')

    clientList.append(tmpNote)


def config_charts():
    logger.debug('config_charts()')

    global mediaPie, wifiPie, signalPie, systemTable, clientTable

    tableHeaders: list = ['Name', 'HostName', 'Manufacturer', 'MAC', 'Reserved IP', 'IP', 'Media', 'Wifi', 'Note']
    systemInfoHeaders: list = ['Type', 'Name', 'Hostname', 'Ip', 'Version', 'Update', 'PkgVersion', 'PkgUpdate']
    media: list = ['Wired', 'Wireless']
    qty: list = [wiredCount, wirelessCount]

    dfSystem = pd.DataFrame(systemInfo)

    systemTable = plotly.graph_objects.Figure(
        data=[plotly.graph_objects.Table(
            header=dict(values=systemInfoHeaders),
            cells=dict(values=[dfSystem.Type, dfSystem.Name, dfSystem.Hostname, dfSystem.Ip, dfSystem.Version, dfSystem.Update, dfSystem.PkgVersion, dfSystem.PkgUpdate]))
        ])

    clientTable = plotly.graph_objects.Figure(
        data=[plotly.graph_objects.Table(
            header=dict(values=tableHeaders),
            cells=dict(values=clientList))
        ])

    mediaPie = plotly.graph_objects.Figure(
        data=[
            plotly.graph_objects.Pie(
                labels=media,
                values=qty,
                hole=0.6)])

    mediaPie.update_traces(
        marker=dict(
            colors=['#1E90FF', '#81C784'],
            line=dict(
                color='#000000',
                width=0.5)))

    mediaPie.update_layout(legend=dict(
        yanchor="top",
        y=0,
        xanchor="right",
        x=0
    ))

    #dfWifi = pd.DataFrame(tmpWifi)

    wifiPie = plotly.graph_objects.Figure(
        data=[
            plotly.graph_objects.Pie(
                labels=uniqueWifiList,
                values=uniqueWifiCountList,
                hole=0.6
            )
        ]
    )

    wifiPie.update_traces(
        marker=dict(
            colors=['#81C784', '#1E90FF', '#F0E68C'],
            line=dict(
                color='#000000',
                width=0.5)))

    wifiPie.update_layout(legend=dict(
        yanchor="top",
        y=0,
        xanchor="right",
        x=0
    ))

    #wifiPie.update_layout(paper_bgcolor="black")

    signalPie = plotly.graph_objects.Figure(
        data=[
            plotly.graph_objects.Pie(
                labels=list(signal_counts.keys()),
                values=list(signal_counts.values()),
                hole=0.6
            )
        ]
    )

    signalPie.update_traces(
        marker=dict(
            colors=['#FA8072', '#EFAB2C', '#F0E68C', '#81C784' ],
            line=dict(
                color='#000000',
                width=0.5)))

    signalPie.update_layout(legend=dict(
        yanchor="top",
        y=0,
        xanchor="right",
        x=0
    ))


def serve_layout():
    logger.debug('serve_layout()')
    fetch_client_data()
    config_charts()
    return html.Div(
        id='layout',
        children=[
            html.Div([html.H1(children='Clients', style={'display': 'inline-block'})]),
            html.Div([html.Div(['Wired/Wireless'], id='ClientMediaHeader', style={'display': 'inline-block'}), dcc.Graph(id="ClientMedia", className='clientMedia', figure=mediaPie), dcc.Interval(id='interval-component', interval=30*1000, n_intervals=0)], style={'margin': '1', 'display': 'inline-block', 'width': '30%'}, id='ClientMediaBlock'),
            html.Div([html.Div(['Wifi Network'], id='ClientWifiHeader', style={'display': 'inline-block'}), dcc.Graph(id="ClientWifi", className='clientWifi', figure=wifiPie), dcc.Interval(id='interval-component2', interval=30*1000, n_intervals=0)], style={'margin': '1', 'display': 'inline-block', 'width': '30%'}, id='ClientWifiBlock'),
            html.Div([html.Div(['Signal Strength'], id='ClientSignalHeader', style={'display': 'inline-block'}), dcc.Graph(id="ClientSignal", className='clientSignal', figure=signalPie), dcc.Interval(id='interval-component3', interval=30*1000, n_intervals=0)], style={'margin': '1', 'display': 'inline-block', 'width': '30%'}, id='ClientSignalBlock'),
            html.Div([dcc.Graph(id='SysInfoTable', className='systemTable', figure=systemTable), dcc.Interval(id='interval-component4', interval=60*1000, n_intervals=0)]),
            html.Div([dcc.Graph(id='Table', className='clientTable', figure=clientTable), dcc.Interval(id='interval-component5', interval=30*1000, n_intervals=0)]),
        ])


app = dash.Dash(__name__, meta_tags=[{ "http-equiv": "refresh", "content": "60" }])

try:
    init_logger()

    # get configuration
    if not fileExists(configFile):
        key = generate_key()
        store_key(key, keyFile)
        
        hst, prt, u, p = get_config_from_user()
        e_u, e_p = encrypt_credentials(u, p, key)

        create_config_file(create_config_dict(hst, prt, e_u, e_p), configFile)

    appConf = read_config_file(configFile)    
    unifiHostName, unifiPort = get_stored_server_config(appConf)
    key = get_key(keyFile)
    uN, pW = get_stored_credentials(appConf)
    unifiUserName, unifiPW = decrypt_credentials(uN, pW, key)

    controller = init_controller()
    fetch_static_data()
    #update_data()

    #config_charts()
    app.layout = serve_layout
except socket.error as se:
    print('Web application server failed to start')
except dash.exceptions as de:
    print(de)

#@app.callback(Output('Table', 'figure'), Input('interval-component4', 'n_intervals'))
#def update_table(n):
#    logger.debug('update_table()')

    #update_data()
    #config_charts()
    #serve_layout()

if __name__ == "__main__":
    logger.debug('main()')
    print('Navigate to http://localhost:8050')
    app.run_server(debug=True, port=8050, host='0.0.0.0')
    logger.debug('done')