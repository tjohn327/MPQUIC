package quic

import (
	"time"

	"github.com/lucas-clemente/quic-go/ackhandler"
	"github.com/lucas-clemente/quic-go/congestion"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
)

const (
	minPathTimer = 10 * time.Millisecond
	// XXX (QDC): To avoid idling...
	maxPathTimer = 1 * time.Second
)

type path struct {
	PathID protocol.PathID
	Conn   connection
	Sess   *session

	RttStats *congestion.RTTStats

	SentPacketHandler     ackhandler.SentPacketHandler
	ReceivedPacketHandler ackhandler.ReceivedPacketHandler

	Open      utils.AtomicBool
	CloseChan chan *qerr.QuicError
	RunClosed chan struct{}

	PotentiallyFailed utils.AtomicBool

	SentPacket          chan struct{}

	// It is now the responsibility of the path to keep its packet number
	PacketNumberGenerator *packetNumberGenerator

	LastRcvdPacketNumber protocol.PacketNumber
	// Used to calculate the next packet number from the truncated wire
	// representation, and sent back in public reset packets
	LargestRcvdPacketNumber protocol.PacketNumber

	LeastUnacked protocol.PacketNumber

	LastNetworkActivityTime time.Time

	Timer           *utils.Timer
}

//add getters
func (p *path) GetConn() connection{
	utils.Debugf("%+v \n", p.Conn.Encode())
	return p.Conn
}

// setup initializes values that are independent of the perspective
func (p *path) setup(oliaSenders map[protocol.PathID]*congestion.OliaSender) {
	p.RttStats = &congestion.RTTStats{}

	var cong congestion.SendAlgorithm

	if p.Sess.version >= protocol.VersionMP && oliaSenders != nil && p.PathID != protocol.InitialPathID {
		cong = congestion.NewOliaSender(oliaSenders, p.RttStats, protocol.InitialCongestionWindow, protocol.DefaultMaxCongestionWindow)
		oliaSenders[p.PathID] = cong.(*congestion.OliaSender)
	}

	sentPacketHandler := ackhandler.NewSentPacketHandler(p.RttStats, cong, p.onRTO)

	now := time.Now()

	p.SentPacketHandler = sentPacketHandler
	p.ReceivedPacketHandler = ackhandler.NewReceivedPacketHandler(p.Sess.version)

	p.PacketNumberGenerator = newPacketNumberGenerator(protocol.SkipPacketAveragePeriodLength)

	p.CloseChan = make(chan *qerr.QuicError, 1)
	p.RunClosed = make(chan struct{}, 1)
	p.SentPacket = make(chan struct{}, 1)

	p.Timer = utils.NewTimer()
	p.LastNetworkActivityTime = now

	p.Open.Set(true)
	p.PotentiallyFailed.Set(false)

	// Once the path is setup, run it
	go p.run()
}

func (p *path) close() error {
	p.Open.Set(false)
	return nil
}

func (p *path) run() {
	// XXX (QDC): relay everything to the session, maybe not the most efficient
runLoop:
	for {
		// Close immediately if requested
		select {
		case <-p.CloseChan:
			break runLoop
		default:
		}

		p.maybeResetTimer()

		select {
		case <-p.CloseChan:
			break runLoop
		case <-p.Timer.Chan():
			p.Timer.SetRead()
			select {
			case p.Sess.pathTimers <- p:
			// XXX (QDC): don't remain stuck here!
			case <-p.CloseChan:
				break runLoop
			case <-p.SentPacket:
				// Don't remain stuck here!
			}
		case <-p.SentPacket:
			// Used to reset the path timer
		}
	}
	p.close()
	p.RunClosed <- struct{}{}
}

func (p *path) SendingAllowed() bool {
	return p.Open.Get() && p.SentPacketHandler.SendingAllowed()
}

func (p *path) GetStopWaitingFrame(force bool) *wire.StopWaitingFrame {
	return p.SentPacketHandler.GetStopWaitingFrame(force)
}

func (p *path) GetAckFrame() *wire.AckFrame {
	ack := p.ReceivedPacketHandler.GetAckFrame()
	if ack != nil {
		ack.PathID = p.PathID
	}

	return ack
}

func (p *path) GetClosePathFrame() *wire.ClosePathFrame {
	closePathFrame := p.ReceivedPacketHandler.GetClosePathFrame()
	if closePathFrame != nil {
		closePathFrame.PathID = p.PathID
	}

	return closePathFrame
}

func (p *path) maybeResetTimer() {
	deadline := p.LastNetworkActivityTime.Add(p.idleTimeout())

	if ackAlarm := p.ReceivedPacketHandler.GetAlarmTimeout(); !ackAlarm.IsZero() {
		deadline = ackAlarm
	}
	if lossTime := p.SentPacketHandler.GetAlarmTimeout(); !lossTime.IsZero() {
		deadline = utils.MinTime(deadline, lossTime)
	}

	deadline = utils.MinTime(utils.MaxTime(deadline, time.Now().Add(minPathTimer)), time.Now().Add(maxPathTimer))

	p.Timer.Reset(deadline)
}

func (p *path) idleTimeout() time.Duration {
	// TODO (QDC): probably this should be refined at path level
	cryptoSetup := p.Sess.cryptoSetup
	if cryptoSetup != nil {
		if p.Open.Get() && (p.PathID != 0 || p.Sess.handshakeComplete) {
			return p.Sess.connectionParameters.GetIdleConnectionStateLifetime()
		}
		return p.Sess.config.HandshakeTimeout
	}
	return time.Second
}

func (p *path) handlePacketImpl(pkt *receivedPacket) error {
	if !p.Open.Get() {
		// Path is closed, ignore packet
		return nil
	}

	if !pkt.rcvTime.IsZero() {
		p.LastNetworkActivityTime = pkt.rcvTime
	}
	hdr := pkt.publicHeader
	data := pkt.data

	// We just received a new packet on that path, so it works
	p.PotentiallyFailed.Set(false)

	// Calculate packet number
	hdr.PacketNumber = protocol.InferPacketNumber(
		hdr.PacketNumberLen,
		p.LargestRcvdPacketNumber,
		hdr.PacketNumber,
	)

	packet, err := p.Sess.unpacker.Unpack(hdr.Raw, hdr, data)
	if utils.Debug() {
		if err != nil {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.PathID)
		} else {
			utils.Debugf("<- Reading packet 0x%x (%d bytes) for connection %x on path %x, %s", hdr.PacketNumber, len(data)+len(hdr.Raw), hdr.ConnectionID, p.PathID, packet.encryptionLevel)
		}
	}

	// if the decryption failed, this might be a packet sent by an attacker
	// don't update the remote address
	if quicErr, ok := err.(*qerr.QuicError); ok && quicErr.ErrorCode == qerr.DecryptionFailure {
		return err
	}
	if p.Sess.perspective == protocol.PerspectiveServer {
		// update the remote address, even if unpacking failed for any other reason than a decryption error
		p.Conn.SetCurrentRemoteAddr(pkt.remoteAddr)
	}
	if err != nil {
		return err
	}

	p.LastRcvdPacketNumber = hdr.PacketNumber
	// Only do this after decrupting, so we are sure the packet is not attacker-controlled
	p.LargestRcvdPacketNumber = utils.MaxPacketNumber(p.LargestRcvdPacketNumber, hdr.PacketNumber)

	isRetransmittable := ackhandler.HasRetransmittableFrames(packet.frames)
	if err = p.ReceivedPacketHandler.ReceivedPacket(hdr.PacketNumber, isRetransmittable); err != nil {
		return err
	}

	if err != nil {
		return err
	}

	return p.Sess.handleFrames(packet.frames, p)
}

func (p *path) onRTO(lastSentTime time.Time) bool {
	// Was there any activity since last sent packet?
	if p.LastNetworkActivityTime.Before(lastSentTime) {
		p.PotentiallyFailed.Set(true)
		p.Sess.schedulePathsFrame()
		return true
	}
	return false
}

func (p *path) SetLeastUnacked(leastUnacked protocol.PacketNumber) {
	p.LeastUnacked = leastUnacked
}
