// Package h264 provides helpers for working with H.264 Annex-B elementary
// streams: NAL unit iteration, SPS extraction and SPS parsing (profile, level
// and frame dimensions, needed for the RTSP SDP and ONVIF responses).
package h264

import (
	"errors"
	"fmt"
)

// startCodeLen returns the length of an Annex-B start code at b[0:].
func startCodeLen(b []byte) int {
	if len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 1 {
		return 4
	}
	if len(b) >= 3 && b[0] == 0 && b[1] == 0 && b[2] == 1 {
		return 3
	}
	return 0
}

// NALU is one NAL unit (start code removed, header byte included).
type NALU struct {
	Type  byte // nal_unit_type (5 bits)
	Bytes []byte
}

// SplitAccessUnit splits an Annex-B access unit into NAL units.
func SplitAccessUnit(au []byte) []NALU {
	var out []NALU
	i := 0
	for i < len(au) {
		n := startCodeLen(au[i:])
		if n == 0 {
			i++
			continue
		}
		start := i + n
		j := start
		for j < len(au) {
			if k := startCodeLen(au[j:]); k > 0 {
				break
			}
			j++
		}
		end := j
		for end > start && au[end-1] == 0 {
			end-- // trailing zeros belong to the next start code
		}
		if end > start {
			out = append(out, NALU{Type: au[start] & 0x1F, Bytes: au[start:end]})
		}
		i = j
	}
	return out
}

// FindNALU returns the NAL units of the requested type.
func FindNALU(au []byte, nalType byte) []NALU {
	var out []NALU
	for _, n := range SplitAccessUnit(au) {
		if n.Type == nalType {
			out = append(out, n)
		}
	}
	return out
}

// SPSInfo contains the SPS fields needed by the proxy.
type SPSInfo struct {
	ProfileIDC byte
	Constraint byte
	LevelIDC   byte
	Width      int // coded width in macroblocks*16 (cropping not applied)
	Height     int // coded height (cropping not applied)
	FPS        float64
}

// removeEmulation strips H.264 emulation-prevention bytes (00 00 03) from a
// NAL payload, returning the RBSP.
func removeEmulation(b []byte) []byte {
	out := make([]byte, 0, len(b))
	zeros := 0
	for i := 0; i < len(b); i++ {
		v := b[i]
		if zeros == 2 && v == 3 {
			// emulation byte dropped
			zeros = 0
			continue
		}
		if v == 0 {
			zeros++
		} else {
			zeros = 0
		}
		out = append(out, v)
	}
	return out
}

// ParseSPS parses an SPS NAL unit (full NAL, header byte included).
func ParseSPS(nalu []byte) (*SPSInfo, error) {
	if len(nalu) < 4 || nalu[0]&0x1F != 7 {
		return nil, errors.New("h264: not an SPS NAL unit")
	}
	rbsp := removeEmulation(nalu[1:]) // strip NAL header + emulation bytes
	if len(rbsp) < 3 {
		return nil, errors.New("h264: SPS too short")
	}
	sps := &SPSInfo{
		ProfileIDC: nalu[1],
		Constraint: nalu[2],
		LevelIDC:   nalu[3],
	}
	r := &bitReader{b: rbsp[3:]}
	if _, err := r.ue(); err != nil { // seq_parameter_set_id
		return nil, err
	}
	if sps.ProfileIDC == 100 || sps.ProfileIDC == 110 || sps.ProfileIDC == 122 ||
		sps.ProfileIDC == 244 || sps.ProfileIDC == 44 || sps.ProfileIDC == 83 ||
		sps.ProfileIDC == 86 || sps.ProfileIDC == 118 || sps.ProfileIDC == 128 {
		if v, err := r.ue(); err != nil { // chroma_format_idc
			return nil, err
		} else if v == 3 {
			if _, err := r.skip(1); err != nil { // separate_colour_plane_flag
				return nil, err
			}
		}
		if _, err := r.ue(); err != nil { // bit_depth_luma_minus8
			return nil, err
		}
		if _, err := r.ue(); err != nil { // bit_depth_chroma_minus8
			return nil, err
		}
		if _, err := r.skip(1); err != nil { // qpprime_y_zero_transform_bypass_flag
			return nil, err
		}
		if flag, err := r.skip(1); err != nil { // seq_scaling_matrix_present_flag
			return nil, err
		} else if flag == 1 {
			count := 8
			if sps.ProfileIDC == 100 || sps.ProfileIDC == 110 ||
				sps.ProfileIDC == 122 || sps.ProfileIDC == 244 || sps.ProfileIDC == 44 {
				count = 12
			}
			for i := 0; i < count; i++ {
				present, err := r.skip(1) // seq_scaling_list_present_flag[i]
				if err != nil {
					return nil, err
				}
				if present == 1 {
					if err := skipScalingList(r, 16); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if _, err := r.ue(); err != nil { // log2_max_frame_num_minus4
		return nil, err
	}
	pocType, err := r.ue()
	if err != nil {
		return nil, err
	}
	switch pocType {
	case 0:
		if _, err := r.ue(); err != nil { // log2_max_pic_order_cnt_lsb_minus4
			return nil, err
		}
		if _, err := r.skip(1); err != nil { // delta_pic_order_always_zero_flag
			return nil, err
		}
	case 1:
		if _, err := r.skip(1); err != nil { // delta_pic_order_always_zero_flag
			return nil, err
		}
		if _, err := r.skip(1); err != nil { // offset_for_non_ref_pic
			return nil, err
		}
		if _, err := r.ue(); err != nil { // num_ref_frames_in_pic_order_cnt_cycle
			return nil, err
		}
	}
	if _, err := r.ue(); err != nil { // max_num_ref_frames
		return nil, err
	}
	if _, err := r.skip(1); err != nil { // gaps_in_frame_num_value_allowed_flag
		return nil, err
	}
	widthMbs, err := r.ue() // pic_width_in_mbs_minus1
	if err != nil {
		return nil, err
	}
	heightMapUnits, err := r.ue() // pic_height_in_map_units_minus1
	if err != nil {
		return nil, err
	}
	frameMbsOnly, err := r.skip(1) // frame_mbs_only_flag
	if err != nil {
		return nil, err
	}
	if _, err := r.skip(1); err != nil { // direct_8x8_inference_flag
		return nil, err
	}
	if flag, err := r.skip(1); err != nil { // frame_cropping_flag
		return nil, err
	} else if flag == 1 {
		for i := 0; i < 4; i++ {
			if _, err := r.ue(); err != nil {
				return nil, err
			}
		}
	}
	if flag, err := r.skip(1); err != nil { // vui_parameters_present_flag
		return nil, err
	} else if flag == 1 {
		if hasTiming, err := r.skip(1); err == nil && hasTiming == 1 {
			numUnits, _ := r.bits(32)
			timeScale, _ := r.bits(32)
			if numUnits != 0 && timeScale != 0 {
				// FPS = time_scale / (2 * num_units_in_tick)
				sps.FPS = float64(timeScale) / (2 * float64(numUnits))
			}
		}
	}
	sps.Width = (int(widthMbs) + 1) * 16
	sps.Height = (int(heightMapUnits) + 1) * 16
	if frameMbsOnly == 0 {
		sps.Height *= 2
	}
	return sps, nil
}

// skipScalingList skips one scaling_list() structure of the given size
// (Rec. ITU-T H.264 §7.3.2.1.1.1).
func skipScalingList(r *bitReader, sizeOfScalingList int) error {
	lastScale, nextScale := 8, 8
	for j := 0; j < sizeOfScalingList; j++ {
		if nextScale != 0 {
			delta, err := r.se()
			if err != nil {
				return err
			}
			nextScale = (lastScale + delta + 256) % 256
		}
		if nextScale != 0 {
			lastScale = nextScale
		}
	}
	return nil
}

// ProfileName converts a profile_idc into a readable name.
func ProfileName(p byte) string {
	switch p {
	case 66:
		return "Baseline"
	case 77:
		return "Main"
	case 88:
		return "Extended"
	case 100:
		return "High"
	default:
		return fmt.Sprintf("Profile-%d", p)
	}
}

// bitReader reads unaligned bits (exp-golomb) from an SPS NAL.
type bitReader struct {
	b   []byte
	pos uint
}

func (r *bitReader) readBit() (uint, error) {
	if int(r.pos>>3) >= len(r.b) {
		return 0, errors.New("h264: unexpected end of SPS")
	}
	bit := uint(r.b[r.pos>>3]>>(7-r.pos&7)) & 1
	r.pos++
	return bit, nil
}

// ue reads an unsigned exp-golomb value.
func (r *bitReader) ue() (uint, error) {
	zeros := 0
	for {
		bit, err := r.readBit()
		if err != nil {
			return 0, err
		}
		if bit == 1 {
			break
		}
		zeros++
		if zeros > 31 {
			return 0, errors.New("h264: invalid exp-golomb")
		}
	}
	v := uint(0)
	for i := 0; i < zeros; i++ {
		bit, err := r.readBit()
		if err != nil {
			return 0, err
		}
		v = v<<1 | bit
	}
	return (1 << uint(zeros)) - 1 + v, nil
}

// se reads a signed exp-golomb value.
func (r *bitReader) se() (int, error) {
	v, err := r.ue()
	if err != nil {
		return 0, err
	}
	if v%2 == 0 {
		return -int(v / 2), nil
	}
	return int(v+1) / 2, nil
}

// skip advances the reader by n bits, returning the value of the first bit.
func (r *bitReader) skip(n uint) (uint, error) {
	v, err := r.readBit()
	if err != nil {
		return 0, err
	}
	for i := uint(1); i < n; i++ {
		if _, err := r.readBit(); err != nil {
			return 0, err
		}
	}
	return v, nil
}

// bits reads up to 64 bits as an unsigned integer (MSB first).
func (r *bitReader) bits(n uint) (uint64, error) {
	var v uint64
	for i := uint(0); i < n; i++ {
		bit, err := r.readBit()
		if err != nil {
			return 0, err
		}
		v = v<<1 | uint64(bit)
	}
	return v, nil
}
