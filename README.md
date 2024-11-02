# [SEED Labs: Cybersecurity Exercises](https://github.com/mutaharmujahid/seedlabs/blob/main/README.md)
This repository contains solutions and documentation for SEED Labs (not all), which are hands-on labs in cybersecurity. The labs cover a wide range of security topics, allowing newbies to explore and understand various types of attacks and defenses.

## Table of Contents

1. [Introduction](#introduction)
2. [Lab Environment Setup](#lab-environment-setup)
3. [Lab Descriptions](#lab-descriptions)
4. [References](#references)
5. [Notes](#notes)

---

## Introduction

**SEED Labs** provide an experiential learning environment for essential cybersecurity concepts. This repository includes solutions, explanations, and, where applicable, code implementations for various labs in the SEED Labs series. Topics covered include:

- Symmetric-Key Encryption
- RSA Public-Key Encryption & Signature Lab
- Web SQL Injection Attack
- Cross-Site Request Forgery Attack
- ARP Cache Poisoning Attack
- ICMP Redirect Attack

These labs offer a practical approach to security and help understand how different types of attacks work in real-world settings.

---

## Lab Environment Setup

### Prerequisites

- **VirtualBox** or another compatible VM software.
- **SEED Ubuntu VM**: Download the SEED Ubuntu VM image from the [SEED Labs website](https://seedsecuritylabs.org/labsetup.html) and import it into your VM software.
- **Tools and Libraries**: Some labs require additional tools like Scapy, Wireshark, etc. Most of the tools are already installed in the VM but if you want to experiment with more tools then feel free to install them within the VM.

### Install SEED VM on VirtualBox
These brief instructions will help you set up the environment on your local machine.

- Step 1: Create a new VM in Virtual Box.
- Step 2: Download the image SEEDUbuntu VM Image from [here](https://seedsecuritylabs.org/labsetup.html).
- Step 3: Use the Virtual Machine Hard Disk file to set up your VM.
- Step 4: Configure the VM.

The [link](https://github.com/seed-labs/seed-labs/blob/master/manuals/vm/seedvm-manual.md) contains a document that can be used to set up the VM.

---

## Lab Descriptions

Below is a summary of the labs included in this repository.

1. **Symmetric Encryption Lab**
    - This lab is to get familiar with the concepts of secret-key encryption and some common attacks on encryption. From this lab, we will gain a first-hand experience on encryption algorithms, encryption modes, paddings, and initial vectors (IV). Moreover, we will be able to use tools and write programs to encrypt/decrypt messages.
2. **RSA Public-Key Encryption & Signature Lab**
    - This lab helps us gain hands-on experience with the RSA algorithm, learning to generate public/private keys, perform encryption/decryption, and create digital signatures. It also enhances understanding by implementing the RSA algorithm using C programming.
3. **Web SQL Injection Attack Lab**
    - In this lab, we have created a web application that is vulnerable to SQL injection attacks. Our goal is to find ways to exploit these vulnerabilities, demonstrate the damage that can be achieved, and master the techniques to defend against such attacks.
4. **Cross-Site Request Forgery (CSRF) Attack Lab**
    - This lab involves launching an ICMP redirect attack, where the victim is manipulated to send packets to a malicious router (10.9.0.111) instead of the intended destination (192.168.60.5). The attacker can then intercept, modify, and relay the packets, demonstrating a man-in-the-middle (MITM) attack.
5. **ARP Cache Poisoning**
    - This lab aims to gain firsthand experience with the ARP cache poisoning attack and learn about the damages it can cause. This lab will use ARP attacks to launch a man-in-the-middle attack, allowing the attacker to intercept and modify packets between two victims, A and B. Skills in packet sniffing and spoofing will also be practiced using Scapy.
6. **ICMP Redirect Attack**
    - This lab involves launching an ICMP redirect attack, where the victim is manipulated to send packets to a malicious router (10.9.0.111) instead of the intended destination (192.168.60.5). The attacker can then intercept, modify, and relay the packets, demonstrating a man-in-the-middle (MITM) attack.


---

## References

- SEED Labs Documentation: [SEED Labs Website](https://seedsecuritylabs.org/Labs_20.04/)
- SEED Labs GitHub Repository: [SEED Labs GitHub](https://github.com/seed-labs/seed-labs)
- [Internet Security: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Internet-Security-Hands-Approach-Computer/dp/1733003967/ref=sr_1_3?crid=2O471TFYX7L4Q&dib=eyJ2IjoiMSJ9.15PFAh9cVEPFZQtcwUWwg2tBRWD4Ddu8JW-Fyh1GZhO1V04holZpPqO3MQLPmgSpbjwOg0FDyzLAdkFRdk9LA54czVxDt4iETkqmL8dEB0B_F3hb7qHEY5Ih5G3_enlSMiTzTRkjznjaxK-TpOsR4Zlh71yuH3HFO35A4bIvSm_Tr_gF8EK_kwtRxh9UTIQq1HgdQuupPwwVCwn6J7s8R0bHpKEon-gDEj8rzetf3EU.WD8Kt2cBOYZrvSwgMmHwwPKo4vim-HKjkXuzbrl28DE&dib_tag=se&keywords=internet+security+book&qid=1730569359&sprefix=internet+security+boo%2Caps%2C126&sr=8-3)

---

## Notes

- **Disclaimer**: This repository is for educational purposes only. Please ensure you have authorization before testing any techniques on a network or system.
- **Happy learning!** If you have suggestions or improvements, open an issue or submit a pull request.
