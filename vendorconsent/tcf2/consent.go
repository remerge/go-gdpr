package vendorconsent

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/prebid/go-gdpr/api"
	"github.com/prebid/go-gdpr/bitutils"
	"github.com/prebid/go-gdpr/consentconstants"
)

const (
	consentStringTCF2Separator  = '.'
	consentStringTCF2Prefix     = 'C'
	segmentTypeDisclosedVendors = 1
)

// ParseString parses the TCF 2.0 vendor string base64 encoded
func ParseString(consent string) (api.VendorConsents, error) {
	if consent == "" {
		return nil, consentconstants.ErrEmptyDecodedConsent
	}

	decoded, coreEnd, err := decodeSegmentFrom(consent, 0)
	if err != nil {
		return nil, err
	}

	metadata, err := ParseCoreSegment(decoded)
	if err != nil {
		return nil, err
	}

	consentMetadata, ok := metadata.(ConsentMetadata)
	if ok && coreEnd < len(consent) {
		segmentStart := coreEnd + 1
		// The segments after the Core String each carry their own segment type,
		// so the spec allows them to appear in any order. Every segment has to be
		// visited: a segment we ignore or cannot decode must not stop the scan,
		// or a DisclosedVendors segment placed after it would be missed.
		for segmentStart < len(consent) {
			segmentDecoded, segmentEnd, err := decodeSegmentFrom(consent, segmentStart)
			if err == nil {
				parseOptionalSegment(segmentDecoded, &consentMetadata)
			}

			segmentStart = segmentEnd + 1
		}
		return consentMetadata, nil
	}
	return metadata, nil
}

func decodeSegmentFrom(consent string, start int) ([]byte, int, error) {
	segmentEnd := strings.IndexByte(consent[start:], consentStringTCF2Separator)
	if segmentEnd == -1 {
		segmentEnd = len(consent)
	} else {
		segmentEnd += start
	}

	buff := []byte(consent[start:segmentEnd])
	decoded := buff
	n, err := base64.RawURLEncoding.Decode(decoded, buff)
	if err != nil {
		return nil, segmentEnd, err
	}
	decoded = decoded[:n:n]

	return decoded, segmentEnd, nil
}

// parseOptionalSegment records the contents of one segment that follows the
// Core String, if it is a segment type this parser reads. Segment types we do
// not read, and segments we cannot decode, are skipped without failing the
// parse: the caller keeps scanning the remaining segments either way.
func parseOptionalSegment(segmentDecoded []byte, metadata *ConsentMetadata) {
	if len(segmentDecoded) == 0 {
		return
	}

	segmentType, err := bitutils.ParseByte3(segmentDecoded, 0)
	if err != nil {
		return
	}

	if segmentType != segmentTypeDisclosedVendors {
		return
	}

	if disclosedVendors, err := parseDisclosedVendorsSegment(segmentDecoded, 3); err == nil {
		metadata.disclosedVendors = disclosedVendors
	}
}

// Parse the core segment from the consent data. Not expected to be encoded in any way.
// It is prefered to use ParseString instead, it parses the optional segments as well.
// Deprecated: Use ParseString instead as it parsed the optional segments as well.
// kept for backwards compatibility.
func Parse(data []byte) (api.VendorConsents, error) {
	return ParseCoreSegment(data)
}

// ParseCoreSegment parses the TCF 2.0 vendor consent data from the string. This string should *not* be encoded (by base64 or any other encoding).
// If the data is malformed and cannot be interpreted as a vendor consent string, this will return an error.
func ParseCoreSegment(data []byte) (api.VendorConsents, error) {
	metadata, err := parseMetadata(data)
	if err != nil {
		return nil, err
	}

	var vendorConsents vendorConsentsResolver
	var vendorLegitInts vendorConsentsResolver

	var legitIntStart uint
	var pubRestrictsStart uint
	// Bit 229 determines whether or not the consent string encodes Vendor data in a RangeSection or BitField.
	// We know from parseMetadata that we have at least 29*8=232 bits available
	if isSet(data, 229) {
		vendorConsents, legitIntStart, err = parseRangeSection(metadata, metadata.MaxVendorID(), 230)
	} else {
		vendorConsents, legitIntStart, err = parseBitField(metadata, metadata.MaxVendorID(), 230)
	}
	if err != nil {
		return nil, err
	}

	metadata.vendorConsents = vendorConsents
	metadata.vendorLegitimateInterestStart = legitIntStart + 17
	legIntMaxVend, err := bitutils.ParseUInt16(data, legitIntStart)
	if err != nil {
		return nil, err
	}

	if legitIntStart+16 >= uint(len(data))*8 {
		return nil, fmt.Errorf("invalid consent data: no legitimate interest start position")
	}
	if isSet(data, legitIntStart+16) {
		vendorLegitInts, pubRestrictsStart, err = parseRangeSection(metadata, legIntMaxVend, metadata.vendorLegitimateInterestStart)
	} else {
		vendorLegitInts, pubRestrictsStart, err = parseBitField(metadata, legIntMaxVend, metadata.vendorLegitimateInterestStart)
	}
	if err != nil {
		return nil, err
	}

	metadata.vendorLegitimateInterests = vendorLegitInts
	metadata.pubRestrictionsStart = pubRestrictsStart

	pubRestrictions, _, err := parsePubRestriction(metadata, pubRestrictsStart)
	if err != nil {
		return nil, err
	}

	metadata.publisherRestrictions = pubRestrictions

	return metadata, err
}

func parseDisclosedVendorsSegment(segmentData []byte, startBit uint) (vendorConsentsResolver, error) {
	if len(segmentData)*8 < int(startBit)+16 {
		return nil, fmt.Errorf("disclosed vendor segment too short")
	}

	maxVendorID, err := bitutils.ParseUInt16(segmentData, startBit)
	if err != nil {
		return nil, err
	}

	if maxVendorID == 0 {
		return nil, nil
	}

	encodingBit := startBit + 16
	if encodingBit >= uint(len(segmentData))*8 {
		return nil, fmt.Errorf("disclosed vendor segment too short for encoding bit")
	}

	tempMetadata := ConsentMetadata{data: segmentData}
	if isSet(segmentData, encodingBit) {
		resolver, _, err := parseRangeSection(tempMetadata, maxVendorID, encodingBit+1)
		return resolver, err
	}
	resolver, _, err := parseBitField(tempMetadata, maxVendorID, encodingBit+1)
	return resolver, err
}

// IsConsentV2 return true if the consent strings looks like a tcf v2 consent string
func IsConsentV2(consent string) bool {
	return len(consent) > 0 && consent[0] == consentStringTCF2Prefix
}
