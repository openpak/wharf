/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026. All rights reserved.                                       *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#version 460

// Composites the system UI overlay (the texture XAM's system command buffer
// resolves into: HUD, Guide, sign-in and the other UI modules) over the guest
// output, stretched to the whole output like the kernel does at swap.

layout(local_size_x = 16, local_size_y = 8, local_size_z = 1) in;

layout(push_constant) uniform XamOverlayConstants {
  uvec2 xe_xam_overlay_size;
  vec2 xe_xam_overlay_size_inv;
};

layout(set = 0, binding = 0, rgb10_a2) uniform image2D xe_xam_overlay_dest;
layout(set = 1, binding = 0) uniform sampler2D xe_xam_overlay_source;

void main() {
  uvec2 pixel_index = gl_GlobalInvocationID.xy;
  if (any(greaterThanEqual(pixel_index, xe_xam_overlay_size))) {
    return;
  }
  vec2 pos = (vec2(pixel_index) + 0.5) * xe_xam_overlay_size_inv;
  vec4 overlay = texture(xe_xam_overlay_source, pos);
  vec4 dest = imageLoad(xe_xam_overlay_dest, ivec2(pixel_index));
  // XAM draws with (SrcAlpha, OneMinusSrcAlpha) over a transparent canvas,
  // which leaves premultiplied colour in the overlay: composite it as such
  // (weighting by alpha again thins out text edges and soft shadows).
  dest.rgb = overlay.rgb + dest.rgb * (1.0 - overlay.a);
  imageStore(xe_xam_overlay_dest, ivec2(pixel_index), vec4(dest.rgb, 1.0));
}
