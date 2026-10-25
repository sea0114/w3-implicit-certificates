| 配置 | 階段 | 原run median ms | 控制run mean ± SD ms | 控制run median ms | 控制／原 median |
| --- | --- | ---: | ---: | ---: | ---: |
| scalar-P256-ECQV | group_setup | 0.005 | 0.001982 ± 0.0004966 | 0.0018 | 0.36 |
| scalar-P256-ECQV | ca_keygen | 0.6051 | 0.54052 ± 0.03074 | 0.53645 | 0.88655 |
| scalar-P256-ECQV | ca_import | 0.5219 | 0.52961 ± 0.0296 | 0.52835 | 1.0124 |
| scalar-P256-ECQV | user_prepare | 0.56255 | 0.545 ± 0.03151 | 0.5426 | 0.96454 |
| scalar-P256-ECQV | issue | 0.8162 | 0.77307 ± 0.03416 | 0.77055 | 0.94407 |
| scalar-P256-ECQV | completion | 0.13055 | 0.13234 ± 0.004768 | 0.1327 | 1.0165 |
| scalar-P256-ECQV | reconstruction | 4.281 | 1.0471 ± 0.03255 | 1.0466 | 0.24446 |
| scalar-P256-ECQV | preimage_validation | 4.8238 | 1.5742 ± 0.04436 | 1.5776 | 0.32703 |
| scalar-P256-PV | group_setup | 0.0029 | 0.001968 ± 0.0004074 | 0.0018 | 0.62069 |
| scalar-P256-PV | ca_keygen | 0.57465 | 0.54395 ± 0.02808 | 0.5445 | 0.94753 |
| scalar-P256-PV | ca_import | 0.515 | 0.53423 ± 0.02763 | 0.5352 | 1.0392 |
| scalar-P256-PV | user_prepare | 0.5609 | 0.54037 ± 0.03024 | 0.5415 | 0.96541 |
| scalar-P256-PV | issue | 0.8046 | 0.77078 ± 0.03358 | 0.7686 | 0.95526 |
| scalar-P256-PV | completion | 0.12875 | 0.13267 ± 0.008465 | 0.1318 | 1.0237 |
| scalar-P256-PV | reconstruction | 1.0713 | 1.0432 ± 0.03548 | 1.0421 | 0.97274 |
| scalar-P256-PV | preimage_validation | 1.5891 | 1.5749 ± 0.04737 | 1.573 | 0.98987 |

跨run比值僅為分開呈現的描述性觀測；非相同coins配對、單一轉換耗時或顯著性結論。

| 階段 | 原run PV／ECQV median | 控制run PV／ECQV median |
| --- | ---: | ---: |
| group_setup | 0.58 | 1 |
| ca_keygen | 0.94968 | 1.015 |
| ca_import | 0.98678 | 1.013 |
| user_prepare | 0.99707 | 0.99797 |
| issue | 0.98579 | 0.99747 |
| completion | 0.98621 | 0.99322 |
| reconstruction | 0.25025 | 0.99575 |
| preimage_validation | 0.32942 | 0.99708 |
