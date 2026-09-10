package vendorconsent

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A short, valid Core String taken from consents.txt. The tests below append
// hand-built optional segments to it, so only the Core String needs to be real.
const testCoreSegment = "CQbVxEAQbVxEAAFADBENCGFgAAAAAAAAACaIAAAAAAAA"

// segmentWriter builds a TC String segment one bit field at a time, so the
// tests can express segments the way the spec tables do.
type segmentWriter struct {
	bits []byte
}

func (w *segmentWriter) writeInt(value uint64, numBits uint) {
	for i := int(numBits) - 1; i >= 0; i-- {
		w.bits = append(w.bits, byte((value>>uint(i))&1))
	}
}

func (w *segmentWriter) bytes() []byte {
	packed := make([]byte, (len(w.bits)+7)/8)
	for i, bit := range w.bits {
		if bit == 1 {
			packed[i/8] |= 0x80 >> uint(i%8)
		}
	}
	return packed
}

func (w *segmentWriter) encode() string {
	return base64.RawURLEncoding.EncodeToString(w.bytes())
}

func (w *segmentWriter) byteLen() int {
	return len(w.bytes())
}

// vendorRange is one RangeEntry. A single vendor is expressed as start == end.
type vendorRange struct {
	start uint16
	end   uint16
}

// disclosedVendorsRange builds a range-encoded DisclosedVendors segment.
func disclosedVendorsRange(maxVendorID uint16, entries ...vendorRange) *segmentWriter {
	w := &segmentWriter{}
	w.writeInt(segmentTypeDisclosedVendors, 3)
	w.writeInt(uint64(maxVendorID), 16)
	w.writeInt(1, 1) // IsRangeEncoding
	w.writeInt(uint64(len(entries)), 12)
	for _, e := range entries {
		if e.start == e.end {
			w.writeInt(0, 1) // IsARange = 0, single vendor
			w.writeInt(uint64(e.start), 16)
			continue
		}
		w.writeInt(1, 1) // IsARange = 1
		w.writeInt(uint64(e.start), 16)
		w.writeInt(uint64(e.end), 16)
	}
	return w
}

// disclosedVendorsBitField builds a bitfield-encoded DisclosedVendors segment.
func disclosedVendorsBitField(maxVendorID uint16, disclosed ...uint16) *segmentWriter {
	isDisclosed := make(map[uint16]bool, len(disclosed))
	for _, id := range disclosed {
		isDisclosed[id] = true
	}

	w := &segmentWriter{}
	w.writeInt(segmentTypeDisclosedVendors, 3)
	w.writeInt(uint64(maxVendorID), 16)
	w.writeInt(0, 1) // IsRangeEncoding = 0, bitfield
	for id := uint16(1); id <= maxVendorID; id++ {
		if isDisclosed[id] {
			w.writeInt(1, 1)
		} else {
			w.writeInt(0, 1)
		}
	}
	return w
}

// publisherTCSegment builds a minimal Publisher TC segment (segment type 3).
// The parser does not read this segment; the tests only need it to be a
// decodable segment of a type we ignore.
func publisherTCSegment() *segmentWriter {
	w := &segmentWriter{}
	w.writeInt(3, 3)  // SegmentType = PublisherTC
	w.writeInt(0, 24) // PubPurposesConsent
	w.writeInt(0, 24) // PubPurposesLITransparency
	w.writeInt(0, 6)  // NumCustomPurposes
	return w
}

// unknownSegment builds a segment with a type this parser does not handle.
// Segment type 2 was the AllowedVendors segment, removed from the spec.
func unknownSegment() *segmentWriter {
	w := &segmentWriter{}
	w.writeInt(2, 3)
	w.writeInt(0, 16)
	return w
}

func joinSegments(core string, segments ...*segmentWriter) string {
	out := core
	for _, s := range segments {
		out += "." + s.encode()
	}
	return out
}

// A range-encoded DisclosedVendors segment is a small, self-contained segment.
// It has no reason to reach the byte length a Core String needs, so the parser
// must not impose one.
func TestDisclosedVendors_RangeEncodingBelowCoreStringMinimum(t *testing.T) {
	segment := disclosedVendorsRange(2000,
		vendorRange{start: 10, end: 10},
		vendorRange{start: 100, end: 200},
	)
	require.Less(t, segment.byteLen(), 31,
		"this test only means something if the segment is shorter than a Core String can be")

	consent, err := ParseString(joinSegments(testCoreSegment, segment))
	require.NoError(t, err)

	assert.Equal(t, uint16(2000), consent.DisclosedVendorsMaxID())
	assert.True(t, consent.DisclosedVendor(10), "single-vendor entry")
	assert.True(t, consent.DisclosedVendor(100), "start of range")
	assert.True(t, consent.DisclosedVendor(150), "inside range")
	assert.True(t, consent.DisclosedVendor(200), "end of range")
	assert.False(t, consent.DisclosedVendor(11), "outside every entry")
	assert.False(t, consent.DisclosedVendor(201), "just past the range")
}

// The same set of vendors must resolve identically whichever encoding the CMP
// chose, at any segment size.
func TestDisclosedVendors_EncodingsAgree(t *testing.T) {
	const maxVendorID = 200
	disclosed := []uint16{5, 100, 101, 102, 192}

	byBitField := disclosedVendorsBitField(maxVendorID, disclosed...)
	byRange := disclosedVendorsRange(maxVendorID,
		vendorRange{start: 5, end: 5},
		vendorRange{start: 100, end: 102},
		vendorRange{start: 192, end: 192},
	)

	fromBitField, err := ParseString(joinSegments(testCoreSegment, byBitField))
	require.NoError(t, err)
	fromRange, err := ParseString(joinSegments(testCoreSegment, byRange))
	require.NoError(t, err)

	require.Equal(t, uint16(maxVendorID), fromBitField.DisclosedVendorsMaxID())
	require.Equal(t, uint16(maxVendorID), fromRange.DisclosedVendorsMaxID())

	for id := uint16(1); id <= maxVendorID; id++ {
		assert.Equal(t, fromBitField.DisclosedVendor(id), fromRange.DisclosedVendor(id),
			"encodings disagree for vendor %d", id)
	}
}

// The spec allows the optional segments to appear in any order, because each
// carries its own segment type. Finding a segment we ignore must not stop the
// scan before the mandatory DisclosedVendors segment.
func TestDisclosedVendors_FoundInAnySegmentOrder(t *testing.T) {
	disclosedVendors := disclosedVendorsBitField(200, 42, 192)

	tests := map[string]string{
		"disclosed vendors only":   joinSegments(testCoreSegment, disclosedVendors),
		"disclosed vendors first":  joinSegments(testCoreSegment, disclosedVendors, publisherTCSegment()),
		"disclosed vendors last":   joinSegments(testCoreSegment, publisherTCSegment(), disclosedVendors),
		"after an unknown segment": joinSegments(testCoreSegment, unknownSegment(), disclosedVendors),
		"between other segments":   joinSegments(testCoreSegment, unknownSegment(), disclosedVendors, publisherTCSegment()),
	}

	for name, consentString := range tests {
		name := name
		consentString := consentString
		t.Run(name, func(t *testing.T) {
			consent, err := ParseString(consentString)
			require.NoError(t, err)

			assert.Equal(t, uint16(200), consent.DisclosedVendorsMaxID())
			assert.True(t, consent.DisclosedVendor(42))
			assert.True(t, consent.DisclosedVendor(192))
			assert.False(t, consent.DisclosedVendor(43))
		})
	}
}

// A segment we cannot decode must not stop the scan either, and must never
// make the whole consent string unparseable.
func TestDisclosedVendors_SurvivesUndecodableSegment(t *testing.T) {
	disclosedVendors := disclosedVendorsBitField(200, 192)

	consent, err := ParseString(testCoreSegment + ".!!!not-base64!!!." + disclosedVendors.encode())
	require.NoError(t, err)

	assert.Equal(t, uint16(200), consent.DisclosedVendorsMaxID())
	assert.True(t, consent.DisclosedVendor(192))
}

// A Core String on its own stays valid, and reports no disclosed vendors
// rather than failing to parse.
func TestDisclosedVendors_AbsentSegment(t *testing.T) {
	consent, err := ParseString(testCoreSegment)
	require.NoError(t, err)

	assert.Equal(t, uint16(0), consent.DisclosedVendorsMaxID())
	assert.False(t, consent.DisclosedVendor(192))
}
