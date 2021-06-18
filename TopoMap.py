import binascii
import select
import time
import struct
from socket import *
import socket
import networkx as nx
import os
import sys
import matplotlib.pyplot as plt
from PyQt5 import QtCore, QtWidgets, QtGui
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib
matplotlib.use('Qt5Agg')

'''
Windows 下使用 Tracert 功能需要关闭防火墙
Linux 下使用需要 root 权限
'''

class Tracert():
    def __init__(self):
        self.ICMP_ECHO_REQUEST = 8
        self.MAX_HOPS = 30
        self.TIMEOUT = 2.0
        self.TRIES = 2

    def checksum(self, str_):
        # In this function we make the checksum of our packet
        str_ = bytearray(str_)
        csum = 0
        countTo = (len(str_) // 2) * 2

        for count in range(0, countTo, 2):
            thisVal = str_[count+1] * 256 + str_[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff

        if countTo < len(str_):
            csum = csum + str_[-1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def build_packet(self):
        myChecksum = 0
        myID = os.getpid() & 0xFFFF
        header = struct.pack(
            "bbHHh", self.ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
        #header = struct.pack("!HHHHH", self.ICMP_ECHO_REQUEST, 0, myChecksum, pid, 1)
        data = struct.pack("d", time.time())
        myChecksum = self.checksum(header + data)
        if sys.platform == 'darwin':
            myChecksum = socket.htons(myChecksum) & 0xffff
        else:
            myChecksum = socket.htons(myChecksum)

        header = struct.pack(
            "bbHHh", self.ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)
        packet = header + data
        return packet

    def get_route(self, hostname):
        timeLeft = self.TIMEOUT
        nodes = []
        for ttl in range(1, self.MAX_HOPS):
            for tries in range(self.TRIES):
                destAddr = gethostbyname(hostname)
                #Fill in start
                # Make a raw socket named mySocket
                icmp = socket.getprotobyname("icmp")
                mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                # mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, icmp)
                mySocket.setsockopt(socket.IPPROTO_IP,
                                    socket.IP_TTL, struct.pack('I', ttl))
                mySocket.settimeout(self.TIMEOUT)
                try:
                    d = self.build_packet()
                    mySocket.sendto(d, (hostname, 0))
                    t = time.time()
                    startedSelect = time.time()
                    whatReady = select.select([mySocket], [], [], timeLeft)
                    howLongInSelect = (time.time() - startedSelect)
                    if whatReady[0] == []:  # Timeout
                        print("*    *    * Request timed out.")
                    recvPacket, addr = mySocket.recvfrom(1024)
                    # print(addr)
                    timeReceived = time.time()
                    timeLeft = timeLeft - howLongInSelect
                    if timeLeft <= 0:
                        print("*    *    * Request timed out.")
                except socket.timeout:
                    continue
                else:
                    icmpHeader = recvPacket[20:28]
                    request_type, code, checksum, packetID, sequence = struct.unpack(
                        "bbHHh", icmpHeader)
                    if request_type == 11:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack(
                            "d", recvPacket[28:28 + bytes])[0]
                        if addr[0] not in nodes:
                            print(" %d   rtt=%.0f ms %s" %
                                  (ttl, (timeReceived - t)*1000, addr[0]))
                            nodes.append(addr[0])
                    elif request_type == 3:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack(
                            "d", recvPacket[28:28 + bytes])[0]
                        if addr[0] not in nodes:
                            print(" %d   rtt=%.0f ms %s" %
                                  (ttl, (timeReceived - t)*1000, addr[0]))
                            nodes.append(addr[0])
                    elif request_type == 0:
                        bytes = struct.calcsize("d")
                        timeSent = struct.unpack(
                            "d", recvPacket[28:28 + bytes])[0]
                        if addr[0] not in nodes:
                            print(" %d   rtt=%.0f ms %s" %
                                  (ttl, (timeReceived - timeSent)*1000, addr[0]))
                            nodes.append(addr[0])
                        return nodes
                    else:
                        # print("error")
                        break
                finally:
                    mySocket.close()
        return nodes


class AddWindow(QtWidgets.QDialog):
    _signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setGeometry(1000, 500, 400, 400)
        self.setWindowTitle('添加节点与路径')

        self.text = QtWidgets.QTextEdit()
        self.addbtn = QtWidgets.QPushButton('添加')

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.text)
        layout.addWidget(self.addbtn)
        self.setLayout(layout)

        self.addbtn.clicked.connect(self.slot1)

    def slot1(self):
        data_str = self.text.toPlainText()
        # 发送信号
        self._signal.emit(data_str)
        self.close()


class TracertWindow(QtWidgets.QDialog):
    _signal = QtCore.pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setGeometry(1000, 500, 400, 400)
        self.setWindowTitle('Trace route')

        self.text = QtWidgets.QLineEdit()
        self.trtbtn = QtWidgets.QPushButton('Trace route')

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.text)
        layout.addWidget(self.trtbtn)
        self.setLayout(layout)

        self.trtbtn.clicked.connect(self.slot1)

    def slot1(self):
        data_str = self.text.text()
        # 发送信号
        self._signal.emit(data_str)
        self.close()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setWindowTitle("Network Topological Map")
        # 重新调整大小
        self.resize(1600, 900)
        # 添加菜单中的按钮
        self.menu = QtWidgets.QMenu("绘图")
        self.menu_draw = QtWidgets.QAction("绘制", self.menu)
        self.menu.addAction(self.menu_draw)
        self.menu_add = QtWidgets.QAction("添加节点与路径", self.menu)
        self.menu.addAction(self.menu_add)
        self.menu_tracert = QtWidgets.QAction("Traceroute", self.menu)
        self.menu.addAction(self.menu_tracert)
        self.menuBar().addMenu(self.menu)
        # 添加事件
        self.menu_draw.triggered.connect(self.plotEvent)
        self.menu_add.triggered.connect(self.addEvent)
        self.menu_tracert.triggered.connect(self.tracertEvent)
        self.setCentralWidget(QtWidgets.QWidget())
        self.edges, self.nodes = [], []
        self.init_graph()
        self.tracert = Tracert()

    def init_graph(self):
        '''
        init_data.txt 格式说明
        初始化网络拓扑图的文件格式：
        p 开始，以下若干行作为一条网络路径的节点
        不同的网络路径用 p 隔开，下例为两个路径的初始化网络拓扑：
        p
        10.19.123.38
        10.255.254.129
        10.255.254.1
        10.80.128.150
        10.80.128.142
        10.208.1.3
        p
        10.203.171.3
        10.203.128.1
        10.255.254.1
        10.80.128.150
        10.80.128.142
        10.208.72.176
        '''
        file_name = "init_data.txt"
        if not os.path.exists(file_name):
            return
        with open(file_name, 'r') as f:
            path_flag = False
            pre_node = ''
            for line in f:
                line = line.strip()
                if len(line) < 1:
                    continue
                if line[0] == 'p':
                    path_flag = True
                else:
                    if path_flag:
                        pre_node = line
                        if pre_node not in self.nodes:
                            self.nodes.append(pre_node)
                        path_flag = False
                    else:
                        if line not in self.nodes:
                            self.nodes.append(line)
                        edge = (pre_node, line)
                        if edge not in self.edges:
                            self.edges.append(edge)
                        pre_node = line
        self.plotEvent()

    def addEvent(self):
        self.add_win = AddWindow()
        self.add_win.show()
        self.add_win._signal.connect(self.add)
        self.add_win.exec_()
        self.plotEvent()

    def add(self, nodes):
        nodes = nodes.split()
        if len(nodes) < 1:
            return
        if nodes[0] not in self.nodes:
            self.nodes.append(nodes[0])
        for i in range(1, len(nodes)):
            if nodes[i] not in self.nodes:
                self.nodes.append(nodes[i])
            edge = (nodes[i-1], nodes[i])
            if edge not in self.edges:
                self.edges.append(edge)

    def tracertEvent(self):
        self.rtr_win = TracertWindow()
        self.rtr_win.show()
        self.rtr_win._signal.connect(self.get_route)
        self.rtr_win.exec_()
        self.plotEvent()

    def get_route(self, hostname):
        # print(hostname)
        nodes = self.tracert.get_route(hostname)
        if len(nodes) < 1:
            return
        if nodes[0] not in self.nodes:
            self.nodes.append(nodes[0])
        for i in range(1, len(nodes)):
            if nodes[i] not in self.nodes:
                self.nodes.append(nodes[i])
            edge = (nodes[i-1], nodes[i])
            if edge not in self.edges:
                self.edges.append(edge)

    # 绘图方法
    def plotEvent(self):
        # 清屏
        plt.cla()
        # 获取绘图并绘制
        fig = plt.figure()
        Graph = nx.Graph()
        for node in self.nodes:
            Graph.add_node(node)
        Graph.add_edges_from(self.edges)
        nx.draw(Graph, with_labels=True, node_color='y',)
        cavans = FigureCanvas(fig)
        # 将绘制好的图像设置为中心 Widget
        self.setCentralWidget(cavans)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    app.exec()
