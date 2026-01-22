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

	decoded, coreEnd, err := decodeBaseSegment(consent)
	if err != nil {
		return nil, err
	}

	metadata, err := Parse(decoded)
	if err != nil {
		return nil, err
	}

	consentMetadata, ok := metadata.(ConsentMetadata)
	if ok && coreEnd < len(consent) {
		parseOptionalSegments(consent, coreEnd, &consentMetadata)
		return consentMetadata, nil
	}
	return metadata, nil
}

func decodeBaseSegment(consent string) ([]byte, int, error) {
	coreEnd := strings.IndexByte(consent, consentStringTCF2Separator)
	if coreEnd == -1 {
		coreEnd = len(consent)
	}

	coreSegment := consent[:coreEnd]
	buff := []byte(coreSegment)
	decoded := buff
	n, err := base64.RawURLEncoding.Decode(decoded, buff)
	if err != nil {
		return nil, 0, err
	}
	decoded = decoded[:n:n]

	return decoded, coreEnd, nil
}

func parseOptionalSegments(consent string, coreEnd int, metadata *ConsentMetadata) {
	segmentStart := coreEnd + 1
	for segmentStart < len(consent) {
		segmentEnd := strings.IndexByte(consent[segmentStart:], consentStringTCF2Separator)

		if segmentEnd == -1 {
			segmentEnd = len(consent)
		} else {
			segmentEnd += segmentStart
		}

		segmentStr := consent[segmentStart:segmentEnd]
		segmentBuff := []byte(segmentStr)
		segmentDecoded := segmentBuff
		segmentN, err := base64.RawURLEncoding.Decode(segmentDecoded, segmentBuff)
		if err != nil {
			segmentStart = segmentEnd + 1
			continue
		}
		segmentDecoded = segmentDecoded[:segmentN]

		if len(segmentDecoded) == 0 {
			segmentStart = segmentEnd + 1
			continue
		}

		segmentType, err := bitutils.ParseByte3(segmentDecoded, 0)
		if err != nil {
			segmentStart = segmentEnd + 1
			continue
		}

		if segmentType == segmentTypeDisclosedVendors {
			disclosedVendors, err := parseDisclosedVendorsSegment(segmentDecoded, 3)
			if err == nil {
				metadata.disclosedVendors = disclosedVendors
				break
			}
		}

		segmentStart = segmentEnd + 1
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
