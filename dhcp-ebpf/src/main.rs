#![no_std]
#![no_main]

mod bindings;

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::{info, trace};
use bindings::{ethhdr, iphdr, udphdr};
use core::{fmt::Display, mem};

#[xdp(name = "dhcp")]
pub fn dhcp(ctx: XdpContext) -> u32 {
    match try_dhcp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

const IPPROTO_UDP: u8 = 0x0011;
const ETH_P_IP: u16 = 0x0800;
const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
const UDP_HDR_LEN: usize = mem::size_of::<udphdr>();

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

fn try_dhcp(ctx: XdpContext) -> Result<u32, u32> {
    let eth = ptr_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;

    if unsafe { u16::from_be((*eth).h_proto) } != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ip).protocol } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp = ptr_at::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let source_port = unsafe { u16::from_be((*udp).source) };
    let destination_port = unsafe { u16::from_be((*udp).dest) };

    // DHCP traffic goes like,
    // 68 port on client to 67 port on server
    // Ignore every thing other than port 68 UDP traffic
    if source_port != 67 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse hostname and MAC address from DHCP packet

    let source_mac = unsafe { (*eth).h_source };
    let destination_mac = unsafe { (*eth).h_dest };
    let source_mac = usize::from_be_bytes([
        0,
        0,
        source_mac[0],
        source_mac[1],
        source_mac[2],
        source_mac[3],
        source_mac[4],
        source_mac[5],
    ]);
    let destination_mac = usize::from_be_bytes([
        0,
        0,
        destination_mac[0],
        destination_mac[1],
        destination_mac[2],
        destination_mac[3],
        destination_mac[4],
        destination_mac[5],
    ]);

    info!(
        &ctx,
        "{:x} {} -> {:x} {}", source_mac, source_port, destination_mac, destination_port
    );

    let dhcp = ptr_at::<DhcpPacket>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)
        .ok_or(xdp_action::XDP_PASS)?;

    info!(
        &ctx,
        "op = {} htype = {} hlen = {} hops = {}",
        unsafe { (*dhcp).operation_type },
        unsafe { (*dhcp).hardware_type },
        unsafe { (*dhcp).hardware_address_length },
        unsafe { (*dhcp).hops }
    );
    info!(&ctx, "txid = {:x}", unsafe {
        (*dhcp).transaction_id.to_be()
    },);
    info!(
        &ctx,
        "secs = {} flags = {:x}",
        unsafe { (*dhcp).seconds_elapsed },
        unsafe { (*dhcp).flags }
    );
    info!(&ctx, "client address = {}", unsafe {
        (*dhcp).client_address
    });
    info!(&ctx, "your address = {}", unsafe { (*dhcp).your_address },);
    info!(&ctx, "next server address = {}", unsafe {
        (*dhcp).next_server_address
    });
    info!(&ctx, "relay agent address = {}", unsafe {
        (*dhcp).relay_agent_address
    });

    let client_address = unsafe { (*dhcp).client_hardware_address };
    info!(
        &ctx,
        "client hardware address = {:x}",
        usize::from_be_bytes([
            0,
            0,
            client_address[0],
            client_address[1],
            client_address[2],
            client_address[3],
            client_address[4],
            client_address[5],
        ])
    );
    info!(&ctx, "magic cookie = {:x}", unsafe {
        (*dhcp).magic_cookie.to_be()
    });

    let udp_payload_size = unsafe { (*udp).len.to_be() };
    info!(&ctx, "packet length = {}", udp_payload_size);

    // 240 fixed bytes in dhcp
    // Keep looping until we get to option 12
    let mut offset = 240;
    let mut count = 0;
    while offset < udp_payload_size as usize && offset < ctx.data_end() {
        let opt_type = unsafe {
            *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset)
                .ok_or(xdp_action::XDP_PASS)?
        };
        let length = unsafe {
            *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 1)
                .ok_or(xdp_action::XDP_PASS)?
        };

        if opt_type == 255 {
            break;
        }

        if opt_type != 15 {
            offset += 2 + length as usize;
            info!(&ctx, "type = {} length = {}", opt_type, length);

            if count >= 70 || offset >= ctx.data_end() {
                break;
            }
        } else {
            // Read body
            info!(&ctx, "found body {} {}", opt_type, length);

            //  info!(
            //      &ctx,
            //      "start from {}",
            //      ctx.data() + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 2,
            //  );

            //            let slice: [u8; 9] = unsafe {
            //                *ptr_at::<[u8; 9]>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 2)
            //                    .ok_or(xdp_action::XDP_PASS)?
            //            };
            //
            //

            //info!(
            //    &ctx,
            //    "offset {}",
            //    ctx.data() + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 1
            //);
            //            info!(&ctx, "ends at {}", ctx.data_end());

            assert!(
                ctx.data() + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 9 + 1
                    < ctx.data_end()
            );
            //            let slice: &[u8] = unsafe {
            //               core::slice::from_raw_parts(
            //                  (ctx.data() + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 1) as *const _,
            //                 length as usize,
            //            )
            //       };
            let slice: &[u8] = unsafe {
                core::slice::from_raw_parts(ctx.data() as *const u8, ctx.data_end() - ctx.data())
            };
            // let slice: [u8; 9] = unsafe {
            //     [
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 2)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 3)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 4)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 5)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 6)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 7)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 8)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 9)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //         *ptr_at::<u8>(&ctx, ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN + offset + 10)
            //             .ok_or(xdp_action::XDP_PASS)?,
            //     ]
            // };

            info!(&ctx, "slice length = {}  ", slice.len(),);

            break;
        }
        count += 1;
    }

    Ok(xdp_action::XDP_PASS)
}

#[repr(C)]
pub struct DhcpPacket {
    operation_type: u8,
    hardware_type: u8,
    hardware_address_length: u8,
    hops: u8,
    transaction_id: u32,
    seconds_elapsed: u16,
    flags: u16,
    client_address: u32,
    your_address: u32,
    next_server_address: u32,
    relay_agent_address: u32,
    client_hardware_address: [u8; 6],
    _client_hardware_padding: [u8; 10],
    _bootp_legacy: [u8; 192],
    magic_cookie: u32,
}

impl Display for DhcpPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "op = {} htype = {} hlen = {} hops = {}",
            self.operation_type, self.hardware_type, self.hardware_address_length, self.hops
        ));
        f.write_fmt(format_args!(
            "op = {} htype = {} hlen = {} hops = {}",
            self.operation_type, self.hardware_type, self.hardware_address_length, self.hops
        ))
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
