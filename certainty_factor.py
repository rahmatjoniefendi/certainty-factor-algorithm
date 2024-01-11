def cari_cf_penyakit(jumlah_pasien_penderita_gejala,
                 total_pasien_suatu_penyakit, digit=2):
    
    nilai_cf_rule = []
    
    for jp, tp in zip(jumlah_pasien_penderita_gejala, total_pasien_suatu_penyakit):
        cf_rule = round(jp / tp, digit)
        nilai_cf_rule.append(cf_rule)
        
    return nilai_cf_rule

def cari_cf_penyakit_labeled(penyakit, jumlah_pasien_penderita_gejala,
                 total_pasien_suatu_penyakit, digit=2):
    
    nilai_cf_rule = []
    indeks = 0
    
    for jp, tp in zip(jumlah_pasien_penderita_gejala, total_pasien_suatu_penyakit):
        cf_rule = round(jp / tp, digit)
        nilai_cf_rule.append((penyakit[indeks], cf_rule))
        indeks += 1
        
    return nilai_cf_rule

def print_proses_merge_cf_rule(cf_rules, index=0, result=0):
    if index == len(cf_rules):
        return result

    print('\t\tCF\t= CF{} + (CF{} * (1 - CF{}))'.format(index+1, index+2, index+1))
    
    print('\t\t\t= {} + ({} * (1 - {}))'.format(cf_rules[index],
                                                cf_rules[index+1],
                                                cf_rules[index]))
    
    print('\t\t\t= {}\n\n'.format(merge_cf_rule(cf_rules, index + 1, (result + (cf_rules[index] * (1 - result))))))
    
    return merge_cf_rule(cf_rules, index + 1, (result + (cf_rules[index] * (1 - result))))


def print_proses(penyakit, cf_gejala, cf_penyakit, rule, penghubung_rule, digit=3):
    gejala = [r[:len(r)-1] for r in rule]
    fakta_baru = []
    cf_rules = []
    for i in range(len(rule)):
        print('{}. IF {} THEN {}\n'.format(
                'R' + str(i+1),
                (' ' + penghubung_rule[i] + ' ').join([str(g) for g in gejala[i]]),
                rule[i][len(rule[i])-1]
            )
        )

        if 0 in [cf_gejala[g] for g in gejala[i]]:
            print('\tR' + str(i+1) + ' Tidak dieksekusi karena ada Evidence yang TIDAK FAKTA\n\n')
            continue
        
        
        print('\tCF{} ({}, {})'.format(str(i+1),
                                     rule[i][len(rule[i])-1],
                                     ' n '.join([g for g in gejala[i]])
                                     )
              )
        
        if penghubung_rule[i] == 'AND':
            print('\t\t= min{} * {}\n'.format(str([str(cf_gejala[g]) for g in gejala[i]]),
                                         cf_penyakit[i]
                                         ))
            g = get_items_from_keys(cf_gejala, gejala[i])
            cf = and_rule(g, cf_penyakit[i], digit)
            print('\t\t= {}'.format(str(cf)))
            fakta_baru.append((penyakit[i], 'CF' + str(i+1) + ' = ' + str(cf)))
            cf_rules.append((penyakit[i], cf))
            print()

            print('\tFAKTA BARU:')
            print('\t\t{}\tHipotesis {}\n\n'.format(penyakit[i],
                                                  cf))
            
        elif penghubung_rule[i] == 'OR':
            print('\t\t=max{} * {}\n'.format(str([str(cf_gejala[g]) for g in gejala[i]]),
                                         rule[i][len(rule[i])-1]
                                         ))
            g = get_items_from_keys(cf_gejala, gejala[i])
            cf = or_rule(cf_gejala, cf_penyakit[i], digit)
            print('\t\t= {}'.format(str(cf)))
            fakta_baru.append((penyakit[i], 'CF' + str(i+1) + ' = ' + str(cf)))
            cf_rules.append((penyakit[i], cf))
            print()
            
            print('\tFAKTA BARU:')
            print('\t\t{}\tHipotesis {}\n\n'.format(penyakit[i],
                                                  fakta_baru[i]))
            

    print('\nFAKTA BARU:\n')
    
    for f in fakta_baru:
        print('\t{}\tHipotesis {}'.format(f[0], f[1]))

    print('\n\n')

    for cf in group_cf_rules(fakta_baru):
        if len(group_cf_rules(fakta_baru)[cf]) > 1:
            
            print('\tKarena {} Hipotesanya sama yaitu {}, maka CF digabungkan\n'
                  .format(' , '.join(['R' + str(i+1) for i in range(len(group_cf_rules(fakta_baru)[cf]))]),
                          cf)
                  )
            print_proses_merge_cf_rule(group_cf_rules(cf_rules)[cf])

    print('\nFAKTA BARU:\n')

    merged_rule = merge_labeled_cf_rules(group_cf_rules(cf_rules))
    
    for k, v in merged_rule.items():
        print('\t{}\tHipotesis {}'.format(k, v))

    print('\n\n\tTerdapat {} Hipotesis dari Fakta Baru yang diperoleh, yaitu {}\n\n'
          .format(len(merged_rule),
                  ' , '.join([k for k in merged_rule.keys()]))
          )


def print_rule(rule, penghubung_rule):
    gejala = [r[:len(r)-1] for r in rule]
    for i in range(len(rule)):
        print('{}. IF {} THEN {}'.format(
                'R' + str(i+1),
                (' ' + penghubung_rule[i] + ' ').join([str(g) for g in gejala[i]]),
                rule[i][len(rule[i])-1]
            )
        )

def group_cf_rules(cf_rules):
    group = {}
    
    for penyakit, cf_penyakit in cf_rules:
        if penyakit in group:
            group[penyakit].append(cf_penyakit)
        else:
            group[penyakit] = [cf_penyakit]

    return group

def merge_labeled_cf_rules(cf_rules_group):
    cf_rules = {}
    
    for cf_rule in cf_rules_group:
        cf_rules[cf_rule] = merge_cf_rule(cf_rules_group[cf_rule])

    return cf_rules


def get_cf_rules(rule, cf_gejala, nama_penyakit, cf_penyakit, penghubung_rule, digit=3):
    gejala = [r[:len(r)-1] for r in rule]

    cf_rules = []
    named_cf_rules = []

    for r in range(len(rule)):
        if penghubung_rule[r] == 'AND':
            g = get_items_from_keys(cf_gejala, gejala[r])
            cf_rule = and_rule(g, cf_penyakit[r], digit)
            cf_rules.append(cf_rule)
            named_cf_rules.append((nama_penyakit[r], cf_rule))
            
        elif penghubung_rule[r] == 'OR':
            g = get_items_from_keys(cf_gejala, gejala[r])
            cf_rule = or_rule(g, cf_penyakit[r], digit)
            cf_rules.append(cf_rule)
            named_cf_rules.append((nama_penyakit[r], cf_rule))
            
    return named_cf_rules


def print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala,
                 total_pasien_suatu_penyakit, digit=2):
    nilai_cf_penyakit = []

    indeks = 0
    for jp, tp in zip(jumlah_pasien_penderita_gejala, total_pasien_suatu_penyakit):
        cf_penyakit = round(jp / tp, digit)
        nilai_cf_penyakit.append(cf_penyakit)
        print('CFRULE{} {}\t = \t{} / {}\t = \t{}'.format(str(indeks+1),
                                                          penyakit[indeks],
                                                          jp,
                                                          tp,
                                                          cf_penyakit)
              )
        indeks += 1
        
    return nilai_cf_penyakit

def print_labeled_rule(rule, cf_gejala, cf_penyakit, penghubung_rule):
    gejala = [r[:len(r)-1] for r in rule]
    
    for i in range(len(rule)):
        print('{}. IF {} THEN {}'.format(
                'R' + str(i+1),
                (' ' + penghubung_rule[i] + ' ').join(
                    [(str(g) + '(' + str(cf_gejala[g]) + ')') for g in gejala[i]]
                ),
                rule[i][len(rule[i])-1] + '(' + str(cf_penyakit[i]) + ')'
            )
        )

def and_rule(cf_gejala, cf_penyakit, digit=3):
    cf_rule = round(min(cf_gejala) * cf_penyakit, digit)
    return cf_rule


def or_rule(cf_gejala, cf_penyakit, digit=3):
    cf_rule = round(max(cf_gejala) * cf_penyakit, digit)
    return cf_rule


def get_items_from_keys(dictionary, keys):
    items = []
    
    for k in keys:
        items.append(dictionary[k])
    return items

def merge_cf_rule(cf_rules, index=0, result=0):
    if index == len(cf_rules):
        return result

    return merge_cf_rule(cf_rules, index + 1, (result + (cf_rules[index] * (1 - result))))

def proses_centainty_factor(rule, cf_gejala, nama_penyakit, cf_penyakit, penghubung_rule, digit=3):
    gejala = [r[:len(r)-1] for r in rule]

    cf_rules = []
    named_cf_rules = []

    for r in range(len(rule)):
        if penghubung_rule[r] == 'AND':
            g = get_items_from_keys(cf_gejala, gejala[r])
            cf_rule = and_rule(g, cf_penyakit[r], digit)
            cf_rules.append(cf_rule)
            named_cf_rules.append((nama_penyakit[r], cf_rule))
            
        elif penghubung_rule[r] == 'OR':
            g = get_items_from_keys(cf_gejala, gejala[r])
            cf_rule = or_rule(g, cf_penyakit[r], digit)
            cf_rules.append(cf_rule)
            named_cf_rules.append((nama_penyakit[r], cf_rule))
            
    print(named_cf_rules)
            
    return cf_rules

def print_tingkat_kepastian(cf_rules, digit=4):
    merged_rule = merge_labeled_cf_rules(group_cf_rules(cf_rules))

    print('+---------------------+----------------------+----------------------+')
    print('|       PENYAKIT      |   TINGKAT KEPASTIAN  | TINGKAT KEPASTIAN(%) |')
    print('+---------------------+----------------------+----------------------+')

    hipotesis_penyakit_terurut = dict(
        sorted(merged_rule.items(), key=lambda x : x[1], reverse=True))
    
    for k, v in hipotesis_penyakit_terurut.items():
        nilai_probabilitas_dlm_persen = round(v, digit) * 100
        print('|{}|{}|{}|'.format(str(k).ljust(21),
                                  str(v).ljust(22),
                                  (str(nilai_probabilitas_dlm_persen) + '%') .ljust(22)))
        
    print('+---------------------+----------------------+----------------------+\n')

    nilai_probabilitas_dlm_persen = round(list(hipotesis_penyakit_terurut.values())[0], digit) * 100
    print('TINGKAT KEPASTIAN TERTINGGI ADALAH PENYAKIT {} DENGAN HIPOTESIS {} atau {}%\n\n'
          .format(list(hipotesis_penyakit_terurut.keys())[0], list(hipotesis_penyakit_terurut.values())[0],
                  round(nilai_probabilitas_dlm_persen, digit)))


def demo_1():
    
    penyakit = [
        'DBD',
        'DBD',
        'TIFOID',
        'TIFOID',
        'MALARIA',
        'MALARIA',
    ]

    jumlah_pasien_penderita_gejala_per_penyakit = [
        55,
        45,
        60,
        20,
        30,
        30
    ]

    total_pasien_suatu_penyakit = [
        100,
        100,
        80,
        80,
        60,
        60
    ]

    jawaban_pasien = {
        'G1'  : 0.8,
        'G2'  : 0.4,
        'G3'  : 0.6,
        'G4'  : 0.2,
        'G5'  : 0.7,
        'G6'  : 0.2,
        'G7'  : 0.5,
        'G8'  : 0.6,
        'G9'  : 0.9,
        'G10' : 0.3,
        'G11' : 0.3,
        'G12' : 0.0
    }

    rule = [
        ['G1', 'G2', 'G3', 'G4', 'G5', 'P1'],
        ['G1', 'G2', 'G5', 'G6', 'P1'],
        ['G1', 'G5', 'G7', 'G8', 'P2'],
        ['G1', 'G3', 'G5', 'G9', 'P2'],
        ['G1', 'G2', 'G3', 'G5', 'G7', 'G10', 'P3'],
        ['G1', 'G2', 'G5', 'G11', 'G12', 'P3'],
    ]

    penghubung_rule = [
        'AND',
        'AND',
        'AND',
        'AND',
        'AND',
        'AND'
    ]
    
    cf_penyakit = cari_cf_penyakit(jumlah_pasien_penderita_gejala_per_penyakit,
                                   total_pasien_suatu_penyakit, 2)

    cf_labeled_penyakit = cari_cf_penyakit_labeled(penyakit,
                                                   jumlah_pasien_penderita_gejala_per_penyakit,
                                                   total_pasien_suatu_penyakit, 2)
    
    print('CF PENYAKIT : ' + str(cf_penyakit))
    print('CF LABELED PENYAKIT : ' + str(cf_labeled_penyakit))

    cf_rule_unmerged = get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4)

    grouped_cf_rule = group_cf_rules(get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4))
    
    print('CF UNMERGED RULE : ' + str(cf_rule_unmerged))
    print('CF GROUPED RULE : ' + str(grouped_cf_rule))

    cf_rule_merged = merge_labeled_cf_rules(grouped_cf_rule)

    print('CF MERGED RULE : ' + str(cf_rule_merged))

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                           1. CFRULE                                   |')
    print('+-----------------------------------------------------------------------+')

    print()    

    print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala_per_penyakit,
                 total_pasien_suatu_penyakit, digit=2)

    print()
    
    print('+-----------------------------------------------------------------------+')
    print('|                              2 . RULE                                 |')
    print('+-----------------------------------------------------------------------+')

    print_labeled_rule(rule, jawaban_pasien, cf_penyakit, penghubung_rule)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                              3 . PROSES                               |')
    print('+-----------------------------------------------------------------------+')

    print_proses(penyakit, jawaban_pasien, cf_penyakit, rule, penghubung_rule, digit=3)


    print()

    print('+-----------------------------------------------------------------------+')
    print('|                        4 . TINGKAT KEPASTIAN                          |')
    print('+-----------------------------------------------------------------------+\n\n')

    print_tingkat_kepastian(cf_rule_unmerged, digit=10000000)
        
def demo_2():
    
    penyakit = [
        'INTERTRIGO',
        'INTERTRIGO',

        
        'MILIARIA',
        'MILIARIA',
        'MILIARIA',
        
        
        'SEBOREA',
        'SEBOREA',
        

        'EKSIM',
        'EKSIM',
        'EKSIM'
    ]

    jumlah_pasien_penderita_gejala_per_penyakit = [
        75,
        50,

        35,
        50,
        25,

        30,
        40,

        50,
        30,
        40
    ]

    total_pasien_suatu_penyakit = [
        125,
        125,

        110,
        110,
        110,

        70,
        70,

        120,
        120,
        120
    ]

    jawaban_pasien = {
        'G1'  : 0.2,
        'G2'  : 0.7,
        'G3'  : 0.8,
        'G4'  : 0.0,
        'G5'  : 0.6,
        'G6'  : 0.0,
        'G7'  : 0.0,
        'G8'  : 0.1,
        'G9'  : 0.35,
        'G10' : 0.0,
        'G11' : 0.4,
        'G12' : 0.7,
        'G13'  : 0.3,
        'G14'  : 0.0,
        'G15'  : 0.2,
        'G16'  : 0.3,
        'G17'  : 0.5,
        'G18'  : 0.0,
        'G19'  : 0.0,
        'G20'  : 0.4,
        'G21'  : 0.45,
        'G22'  : 0.0
    }

    rule = [
        #['G3', 'G4', 'G6', 'G9', 'G12', 'G15', 'G18', 'G19', 'P1'],
        ['G5', 'G11', 'G12', 'G15', 'P1'],
        ['G5', 'G6', 'G11', 'G15', 'G17', 'P1'],
        
        
        
        #['G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8', 'G10', 'G11', 'G16', 'P2'],
        ['G1', 'G2', 'G16', 'G20', 'P2'],
        ['G2', 'G3', 'G4', 'G16', 'G20', 'P2'],
        ['G2', 'G3', 'G13', 'G14', 'G20', 'P2'],

        
        #['G1', 'G4', 'G6', 'G11', 'G13', 'G14', 'G16', 'G17', 'P3'],
        ['G18', 'G19', 'G22', 'P3'],
        ['G7', 'G19', 'G22', 'P3'],

        ['G5', 'G8', 'G9', 'G10', 'G17', 'P4'],
        ['G5', 'G6', 'G8', 'G17', 'P4'],
        ['G5', 'G9', 'G21', 'P4']
    ]

    penghubung_rule = [
        'AND',
        'AND',
        
        'AND',
        'AND',
        'AND',
        
        'AND',
        'AND',

        'AND',
        'AND',
        'AND'
    ]
    
    cf_penyakit = cari_cf_penyakit(jumlah_pasien_penderita_gejala_per_penyakit,
                                   total_pasien_suatu_penyakit, 2)

    cf_labeled_penyakit = cari_cf_penyakit_labeled(penyakit,
                                                   jumlah_pasien_penderita_gejala_per_penyakit,
                                                   total_pasien_suatu_penyakit, 2)
                                                   
    
    print('CF PENYAKIT : ' + str(cf_penyakit))
    print('CF LABELED PENYAKIT : ' + str(cf_labeled_penyakit))

    cf_rule_unmerged = get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4)

    grouped_cf_rule = group_cf_rules(get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4))
    
    print('CF UNMERGED RULE : ' + str(cf_rule_unmerged))
    print('CF GROUPED RULE : ' + str(grouped_cf_rule))

    cf_rule_merged = merge_labeled_cf_rules(grouped_cf_rule)    

    print('CF MERGED RULE : ' + str(cf_rule_merged))

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                           1. CFRULE                                   |')
    print('+-----------------------------------------------------------------------+')

    print()    

    print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala_per_penyakit,
                 total_pasien_suatu_penyakit, digit=4)

    print()
    
    print('+-----------------------------------------------------------------------+')
    print('|                              2 . RULE                                 |')
    print('+-----------------------------------------------------------------------+')

    print_labeled_rule(rule, jawaban_pasien, cf_penyakit, penghubung_rule)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                              3 . PROSES                               |')
    print('+-----------------------------------------------------------------------+')

    print_proses(penyakit, jawaban_pasien, cf_penyakit, rule, penghubung_rule, digit=4)


    print()

    print('+-----------------------------------------------------------------------+')
    print('|                        4 . TINGKAT KEPASTIAN                          |')
    print('+-----------------------------------------------------------------------+\n\n')

    print_tingkat_kepastian(cf_rule_unmerged, digit=10000000)

def demo_3():
    
    penyakit = [
        'DBD',
        'DBD',
        'DBD',
        
        'MALARIA',
        'MALARIA',
        'MALARIA',
        
        'CHIKUNGUYA',
        'CHIKUNGUYA',
        'CHIKUNGUYA',
    ]

    jumlah_pasien_penderita_gejala_per_penyakit = [
        29,
        37,
        23,

        20,
        25,
        11,

        8,
        5,
        9
    ]

    total_pasien_suatu_penyakit = [
        89,
        89,
        89,

        56,
        56,
        56,

        22,
        22,
        22
    ]

    jawaban_pasien = {
        'G1'  : 0.35,
        'G2'  : 0.85,
        'G3'  : 0.40,
        'G4'  : 0.80,
        'G5'  : 0.0,
        'G6'  : 0.55,
        'G7'  : 0.15,
        'G8'  : 0.50,
        'G9'  : 0.10,
        'G10' : 0.0,
        'G11' : 0.30,
        'G12' : 0.35,
        'G13'  : 0.0,
        'G14'  : 0.10,
        'G15'  : 0.50,
        'G16'  : 0.90,
        'G17'  : 0.25,
        'G18'  : 0.30,
        'G19'  : 0.0
    }

    rule = [
        #['G3', 'G4', 'G6', 'G9', 'G12', 'G15', 'G18', 'G19', 'P1'],
        ['G3', 'G4', 'G6', 'G9', 'G15', 'P1'],
        ['G3', 'G6', 'G15', 'G19', 'P1'],
        ['G3', 'G4', 'G9', 'G12', 'G18', 'P1'],
        
        #['G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8', 'G10', 'G11', 'G16', 'P2'],
        ['G2', 'G3', 'G4', 'G8', 'P2'],
        ['G3', 'G4', 'G7', 'G16', 'P2'],
        ['G3', 'G5', 'G6', 'G10', 'G11', 'P2'],

        
        #['G1', 'G4', 'G6', 'G11', 'G13', 'G14', 'G16', 'G17', 'P3'],
        ['G1', 'G6', 'G14', 'G16', 'G17', 'P3'],
        ['G1', 'G4', 'G16', 'G17', 'P3'],
        ['G1', 'G4', 'G11', 'G13', 'P3']
    ]

    penghubung_rule = [
        'AND',
        'AND',
        'AND',
        
        'AND',
        'AND',
        'AND',
        
        'AND',
        'AND',
        'AND'
    ]
    
    cf_penyakit = cari_cf_penyakit(jumlah_pasien_penderita_gejala_per_penyakit,
                                   total_pasien_suatu_penyakit, 2)

    cf_labeled_penyakit = cari_cf_penyakit_labeled(penyakit,
                                                   jumlah_pasien_penderita_gejala_per_penyakit,
                                                   total_pasien_suatu_penyakit, 2)
                                                   
    
    print('CF PENYAKIT : ' + str(cf_penyakit))
    print('CF LABELED PENYAKIT : ' + str(cf_labeled_penyakit))

    cf_rule_unmerged = get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4)

    grouped_cf_rule = group_cf_rules(get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4))
    
    print('CF UNMERGED RULE : ' + str(cf_rule_unmerged))
    print('CF GROUPED RULE : ' + str(grouped_cf_rule))

    cf_rule_merged = merge_labeled_cf_rules(grouped_cf_rule)

    print('CF MERGED RULE : ' + str(cf_rule_merged))

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                           1. CFRULE                                   |')
    print('+-----------------------------------------------------------------------+')

    print()    

    print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala_per_penyakit,
                 total_pasien_suatu_penyakit, digit=4)

    print()
    
    print('+-----------------------------------------------------------------------+')
    print('|                              2 . RULE                                 |')
    print('+-----------------------------------------------------------------------+')

    print_labeled_rule(rule, jawaban_pasien, cf_penyakit, penghubung_rule)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                              3 . PROSES                               |')
    print('+-----------------------------------------------------------------------+')

    print_proses(penyakit, jawaban_pasien, cf_penyakit, rule, penghubung_rule, digit=4)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                        4 . TINGKAT KEPASTIAN                          |')
    print('+-----------------------------------------------------------------------+\n\n')

    print_tingkat_kepastian(cf_rule_unmerged, digit=10000000)
        

def demo_4():
    
    penyakit = [
        'P1 (MALARIA TROPICA)',
        'P1 (MALARIA TROPICA)',

        
        'P2 (MALARIA TERTIANA)',
        'P2 (MALARIA TERTIANA)',
        
        
        'P3 (MALARIA QUARTANA)',
        'P3 (MALARIA QUARTANA)',
    ]

    jumlah_pasien_penderita_gejala_per_penyakit = [
        55,
        50,

        35,
        65,

        40,
        45
    ]

    total_pasien_suatu_penyakit = [
        105,
        105,

        100,
        100,

        85,
        85
    ]

    jawaban_pasien = {
        'G1'  : 0.15,
        'G2'  : 0.5,
        'G3'  : 0.8,
        'G4'  : 0.0,
        'G5'  : 0.0,
        'G6'  : 0.35,
        'G7'  : 0.25,
        'G8'  : 0.8,
        'G9'  : 0.85,
        'G10' : 0.0,
        'G11' : 0.55,
        'G12' : 0.3
    }

    rule = [
        #['G3', 'G4', 'G6', 'G9', 'G12', 'G15', 'G18', 'G19', 'P1'],
        ['G4', 'G8', 'G10', 'G11', 'P1'],
        ['G3', 'G6', 'G9', 'G12', 'P1'],
        
        
        #['G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8', 'G10', 'G11', 'G16', 'P2'],
        ['G2', 'G7', 'G8', 'G12', 'P2'],
        ['G1', 'G2', 'G7', 'G11', 'G12', 'P2'],

        
        #['G1', 'G4', 'G6', 'G11', 'G13', 'G14', 'G16', 'G17', 'P3'],
        ['G2', 'G5', 'G8', 'P3'],
        ['G7', 'G8', 'G11', 'G12', 'P3']
    ]

    penghubung_rule = [
        'AND',
        'AND',
        
        'AND',
        'AND',
        
        'AND',
        'AND'
    ]
    
    cf_penyakit = cari_cf_penyakit(jumlah_pasien_penderita_gejala_per_penyakit,
                                   total_pasien_suatu_penyakit, 2)

    cf_labeled_penyakit = cari_cf_penyakit_labeled(penyakit,
                                                   jumlah_pasien_penderita_gejala_per_penyakit,
                                                   total_pasien_suatu_penyakit, 2)
    
    print('CF PENYAKIT : ' + str(cf_penyakit))
    print('CF LABELED PENYAKIT : ' + str(cf_labeled_penyakit))

    cf_rule_unmerged = get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4)

    grouped_cf_rule = group_cf_rules(get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4))
    
    print('CF UNMERGED RULE : ' + str(cf_rule_unmerged))
    print('CF GROUPED RULE : ' + str(grouped_cf_rule))

    cf_rule_merged = merge_labeled_cf_rules(grouped_cf_rule)    

    print('CF MERGED RULE : ' + str(cf_rule_merged))

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                           1. CFRULE                                   |')
    print('+-----------------------------------------------------------------------+')

    print()    

    print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala_per_penyakit,
                 total_pasien_suatu_penyakit, digit=4)

    print()
    
    print('+-----------------------------------------------------------------------+')
    print('|                              2 . RULE                                 |')
    print('+-----------------------------------------------------------------------+')

    print_labeled_rule(rule, jawaban_pasien, cf_penyakit, penghubung_rule)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                              3 . PROSES                               |')
    print('+-----------------------------------------------------------------------+')

    print_proses(penyakit, jawaban_pasien, cf_penyakit, rule, penghubung_rule, digit=4)


    print()

    print('+-----------------------------------------------------------------------+')
    print('|                        4 . TINGKAT KEPASTIAN                          |')
    print('+-----------------------------------------------------------------------+\n\n')

    print_tingkat_kepastian(cf_rule_unmerged, digit=10000000)


def demo_5():
    
    penyakit = [
        'P1 (MALARIA TROPICA)',
        
        'P2 (MALARIA TERTIANA)',
        
        'P3 (MALARIA QUARTANA)'
    ]

    jumlah_pasien_penderita_gejala_per_penyakit = [
        105,
        
        100,

        85
    ]

    total_pasien_suatu_penyakit = [
        105,

        100,

        85,
    ]

    jawaban_pasien = {
        'G1'  : 0.15,
        'G2'  : 0.5,
        'G3'  : 0.8,
        'G4'  : 0.0,
        'G5'  : 0.0,
        'G6'  : 0.35,
        'G7'  : 0.25,
        'G8'  : 0.8,
        'G9'  : 0.85,
        'G10' : 0.0,
        'G11' : 0.55,
        'G12' : 0.3
    }

    rule = [
        #['G3', 'G4', 'G6', 'G9', 'G12', 'G15', 'G18', 'G19', 'P1'],
        ['G3', 'G6', 'G9', 'G12', 'G4', 'G8', 'G10', 'G11', 'P1'],
        
        
        #['G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8', 'G10', 'G11', 'G16', 'P2'],
        ['G1', 'G2', 'G7', 'G8', 'G11', 'G12', 'P2'],

        
        #['G1', 'G4', 'G6', 'G11', 'G13', 'G14', 'G16', 'G17', 'P3'],
        ['G2', 'G5', 'G7', 'G8', 'G11', 'G12', 'P3']
    ]

    penghubung_rule = [
        'AND',
        
        'AND',
        
        'AND'
    ]
    
    cf_penyakit = cari_cf_penyakit(jumlah_pasien_penderita_gejala_per_penyakit,
                                   total_pasien_suatu_penyakit, 2)

    cf_labeled_penyakit = cari_cf_penyakit_labeled(penyakit,
                                                   jumlah_pasien_penderita_gejala_per_penyakit,
                                                   total_pasien_suatu_penyakit, 2)
    
    print('CF PENYAKIT : ' + str(cf_penyakit))
    print('CF LABELED PENYAKIT : ' + str(cf_labeled_penyakit))

    cf_rule_unmerged = get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4)

    grouped_cf_rule = group_cf_rules(get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4))
    
    print('CF UNMERGED RULE : ' + str(cf_rule_unmerged))
    print('CF GROUPED RULE : ' + str(grouped_cf_rule))

    cf_rule_merged = merge_labeled_cf_rules(grouped_cf_rule)    

    print('CF MERGED RULE : ' + str(cf_rule_merged))

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                           1. CFRULE                                   |')
    print('+-----------------------------------------------------------------------+')

    print()    

    print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala_per_penyakit,
                 total_pasien_suatu_penyakit, digit=4)

    print()
    
    print('+-----------------------------------------------------------------------+')
    print('|                              2 . RULE                                 |')
    print('+-----------------------------------------------------------------------+')

    print_labeled_rule(rule, jawaban_pasien, cf_penyakit, penghubung_rule)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                              3 . PROSES                               |')
    print('+-----------------------------------------------------------------------+')

    print_proses(penyakit, jawaban_pasien, cf_penyakit, rule, penghubung_rule, digit=4)


    print()

    print('+-----------------------------------------------------------------------+')
    print('|                        4 . TINGKAT KEPASTIAN                          |')
    print('+-----------------------------------------------------------------------+\n\n')

    print_tingkat_kepastian(cf_rule_unmerged, digit=10000000)


def demo_6():
    
    penyakit = [
        'P1 (Quail Enteritis)',
        
        'P2 (Tatelo)',
        
        'P3 (Pullorum)',
        
        'P4 (Coccidiosis)',
        
        'P5 (Bronchitis)',

        'P6 (Coryza)',
        
    ]

    jumlah_pasien_penderita_gejala_per_penyakit = [
        105,
        
        100,

        85
    ]

    total_pasien_suatu_penyakit = [
        105,

        100,

        85,
    ]

    jawaban_pasien = {
        'G1'  : 0.15,
        'G2'  : 0.5,
        'G3'  : 0.8,
        'G4'  : 0.0,
        'G5'  : 0.0,
        'G6'  : 0.35,
        'G7'  : 0.25,
        'G8'  : 0.8,
        'G9'  : 0.85,
        'G10' : 0.0,
        'G11' : 0.55,
        'G12' : 0.3
    }

    rule = [
        # ['G3', 'G4', 'G6', 'G9', 'G12', 'G15', 'G18', 'G19', 'P1'],
        ['G3', 'G6', 'G9', 'G12', 'G4', 'G8', 'G10', 'G11', 'P1'],
        
        
        # ['G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8', 'G10', 'G11', 'G16', 'P2'],
        ['G1', 'G2', 'G7', 'G8', 'G11', 'G12', 'P2'],

        
        # ['G1', 'G4', 'G6', 'G11', 'G13', 'G14', 'G16', 'G17', 'P3'],
        ['G2', 'G5', 'G7', 'G8', 'G11', 'G12', 'P3']
    ]

    penghubung_rule = [
        'AND',
        
        'AND',
        
        'AND'
    ]
    
    cf_penyakit = cari_cf_penyakit(jumlah_pasien_penderita_gejala_per_penyakit,
                                   total_pasien_suatu_penyakit, 2)

    cf_labeled_penyakit = cari_cf_penyakit_labeled(penyakit,
                                                   jumlah_pasien_penderita_gejala_per_penyakit,
                                                   total_pasien_suatu_penyakit, 2)
    
    print('CF PENYAKIT : ' + str(cf_penyakit))
    print('CF LABELED PENYAKIT : ' + str(cf_labeled_penyakit))

    cf_rule_unmerged = get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4)

    grouped_cf_rule = group_cf_rules(get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4))
    
    print('CF UNMERGED RULE : ' + str(cf_rule_unmerged))
    print('CF GROUPED RULE : ' + str(grouped_cf_rule))


    cf_rule_merged = merge_labeled_cf_rules(grouped_cf_rule)
    

    print('CF MERGED RULE : ' + str(cf_rule_merged))

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                           1. CFRULE                                   |')
    print('+-----------------------------------------------------------------------+')

    print()    

    print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala_per_penyakit,
                 total_pasien_suatu_penyakit, digit=4)

    print()
    
    print('+-----------------------------------------------------------------------+')
    print('|                              2 . RULE                                 |')
    print('+-----------------------------------------------------------------------+')

    print_labeled_rule(rule, jawaban_pasien, cf_penyakit, penghubung_rule)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                              3 . PROSES                               |')
    print('+-----------------------------------------------------------------------+')

    print_proses(penyakit, jawaban_pasien, cf_penyakit, rule, penghubung_rule, digit=4)


    print()

    print('+-----------------------------------------------------------------------+')
    print('|                        4 . TINGKAT KEPASTIAN                          |')
    print('+-----------------------------------------------------------------------+\n\n')

    print_tingkat_kepastian(cf_rule_unmerged, digit=10000000)


def demo_7():
    
    penyakit = [
        'P1 (Gastritis)',
        'P1 (Gastritis)',
        
        'P2 (Dispepsia)',
        
        'P3 (Peptic (Tukak Lambung))',
        
        'P4 (Gastroesophageal Reflux Disease (GERD))',
        
        'P5 (Gaster (Kanker Lambung))'    
    ]

    jumlah_pasien_penderita_gejala_per_penyakit = [
        100,
        100,
        100,
        100,
        100,
        100,
    ]

    total_pasien_suatu_penyakit = [
        100,
        100,
        100,
        100,
        100,
        100,
    ]

    jawaban_pasien = {
        'G1'  : 1.0,
        'G2'  : 1.0,
        'G3'  : 1.0,
        'G4'  : 1.0,
        'G5'  : 1.0,
        'G6'  : 1.0,
        'G7'  : 1.0,
        'G8'  : 1.0,
        'G9'  : 1.0,
        'G10' : 1.0,
        'G11' : 1.0,
        'G12' : 1.0,
        'G13' : 1.0,
        'G14' : 1.0,
        'G15' : 1.0,
        'G16' : 1.0,
        'G17' : 1.0,
        'G18' : 1.0,
        'G19' : 1.0,
        'G20' : 1.0,
        'G21' : 0
    }

    rule = [
        ['G1', 'G2', 'G3', 'G6', 'G7', 'G16', 'G17', 'G18', 'P1'],
        ['G1', 'G2', 'G3', 'G6', 'G7', 'G16', 'G17', 'G18', 'P1'],
        ['G1', 'G3', 'G4', 'G7', 'G13', 'G14', 'G16', 'G18', 'G20', 'P2'],
        ['G1', 'G2', 'G4', 'G5', 'G6', 'G7', 'G18', 'G21', 'P3'],
        ['G2', 'G3', 'G8', 'G9', 'G10', 'G11', 'G15', 'G18', 'G19', 'P4'],
        ['G1' ,'G2', 'G3', 'G6', 'G8', 'G12', 'G15', 'G16', 'G18', 'P5']
    ];

    penghubung_rule = [
        'AND',
        'AND',
        'AND',
        
        'AND',
        
        'AND',
        
        'AND',
        
        'AND'
    ]
    
    cf_penyakit = cari_cf_penyakit(jumlah_pasien_penderita_gejala_per_penyakit,
                                   total_pasien_suatu_penyakit, 2)

    cf_labeled_penyakit = cari_cf_penyakit_labeled(penyakit,
                                                   jumlah_pasien_penderita_gejala_per_penyakit,
                                                   total_pasien_suatu_penyakit, 2)
    
    print('CF PENYAKIT : ' + str(cf_penyakit))
    print('CF LABELED PENYAKIT : ' + str(cf_labeled_penyakit))

    cf_rule_unmerged = get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4)

    grouped_cf_rule = group_cf_rules(get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4))
    
    print('CF UNMERGED RULE : ' + str(cf_rule_unmerged))
    print('CF GROUPED RULE : ' + str(grouped_cf_rule))

    cf_rule_merged = merge_labeled_cf_rules(grouped_cf_rule)
        

    print('CF MERGED RULE : ' + str(cf_rule_merged))

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                           1. CFRULE                                   |')
    print('+-----------------------------------------------------------------------+')

    print()    

    print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala_per_penyakit,
                 total_pasien_suatu_penyakit, digit=4)

    print()
    
    print('+-----------------------------------------------------------------------+')
    print('|                              2 . RULE                                 |')
    print('+-----------------------------------------------------------------------+')

    print_labeled_rule(rule, jawaban_pasien, cf_penyakit, penghubung_rule)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                              3 . PROSES                               |')
    print('+-----------------------------------------------------------------------+')

    print_proses(penyakit, jawaban_pasien, cf_penyakit, rule, penghubung_rule, digit=4)


    print()

    print('+-----------------------------------------------------------------------+')
    print('|                        4 . TINGKAT KEPASTIAN                          |')
    print('+-----------------------------------------------------------------------+\n\n')

    print_tingkat_kepastian(cf_rule_unmerged, digit=10000000)


def demo_8():
    
    penyakit = [
        'P1 (Gastritis)',
        'P1 (Gastritis)',
        'P1 (Gastritis)',
        'P1 (Gastritis)',
        
        'P2 (Dispepsia)',
        'P2 (Dispepsia)',
        'P2 (Dispepsia)',
        'P2 (Dispepsia)',
        'P2 (Dispepsia)',
        'P2 (Dispepsia)',
        
        'P3 (Peptic)',
        'P3 (Peptic)',
        'P3 (Peptic)',
        'P3 (Peptic)',
        'P3 (Peptic)',
        
        'P4 (GERD)',
        'P4 (GERD)',
        'P4 (GERD)',
        'P4 (GERD)',
        'P4 (GERD)',
        'P4 (GERD)',
        'P4 (GERD)',
    ]

    jumlah_pasien_penderita_gejala_per_penyakit = [
        80,
        60,
        60,
        60,

        80,
        80,
        60,
        60,
        60,
        60,

        80,
        60,
        60,
        60,
        60,

        80,
        80,
        80,
        60,
        60,
        60
    ]

    total_pasien_suatu_penyakit = [
        100,
        100,
        100,
        100,
        100,

        100,
        100,
        100,
        100,
        100,

        100,
        100,
        100,
        100,
        100,

        100,
        100,
        100,
        100,
        100,
        100,
    ]

    gejala_penyakit = [
        'G1',
        'G2',
        'G3',
        'G4',
        'G5',
        'G6',
        'G7',
        'G8',
        'G9',
        'G10',
        'G11',
        'G12',
        'G13',
        'G14',
        'G15',
        'G16',
        'G17',
        'G18',
        'G19',
        'G20',
    ]

    # G2, G3, G8, G9, G11, G15
    jawaban_pasien = {
        'G1'  : 0.0,
        'G2'  : 1.0,
        'G3'  : 0.2,
        'G4'  : 0.0,
        'G5'  : 0.0,
        'G6'  : 0.0,
        'G7'  : 0.0,
        'G8'  : 0.6,
        'G9'  : 1.0,
        'G10' : 0.0,
        'G11' : 1.0,
        'G12' : 0.0,
        'G13' : 0.0,
        'G14' : 0.0,
        'G15' : 1.0,
        'G16' : 0.0,
        'G17' : 0.0,
        'G18' : 0.0,
        'G19' : 0.0,
        'G20' : 0.0,
    }
    

    rule = [
        ['G6', 'G16', 'G17', 'P1'],
        ['G1', 'G2', 'G3', 'G7', 'P1'],
        ['G1', 'G3', 'G7', 'G18', 'P1'],
        ['G2', 'G6', 'G16', 'G18', 'P1'],


        ['G13', 'G14', 'G20', 'P2'],
        ['G4', 'G13', 'G14', 'G16', 'G18', 'P2'],
        ['G4', 'G7', 'G16', 'P2'],
        ['G1', 'G3', 'G7', 'G13', 'P2'],
        ['G1', 'G3', 'G7', 'G14', 'P2'],
        ['G1', 'G17', 'G18', 'G20', 'P2'],

        ['G5', 'G6', 'G12', 'G18', 'P3'],
        ['G5', 'G12', 'P3'],
        ['G1', 'G7', 'G12', 'G18', 'P3'],
        ['G1', 'G2', 'G4', 'G5', 'P3'],
        ['G1', 'G2', 'G7', 'G12', 'P3'],
        
        ['G8', 'G9', 'G10', 'G11', 'G15', 'P4'],
        ['G8', 'G9', 'G10', 'G15', 'P4'],
        ['G8', 'G9', 'G11', 'G15', 'P4'],
        ['G2', 'G3', 'G8', 'G9', 'P4'],
        ['G11', 'G15', 'G19', 'P4'],
        ['G8', 'G10', 'G19', 'P4']

        
    ];

    penghubung_rule = [
        'AND',
        'AND',
        'AND',
        'AND',
        
        'AND',
        'AND',
        'AND',
        'AND',
        'AND',
        'AND',

        'AND',
        'AND',
        'AND',
        'AND',
        'AND',
        'AND',

        'AND',
        'AND',
        'AND',
        'AND',
        'AND',
    ]
    
    cf_penyakit = cari_cf_penyakit(jumlah_pasien_penderita_gejala_per_penyakit,
                                   total_pasien_suatu_penyakit, 2)

    cf_labeled_penyakit = cari_cf_penyakit_labeled(penyakit,
                                                   jumlah_pasien_penderita_gejala_per_penyakit,
                                                   total_pasien_suatu_penyakit, 2)
    
    print('CF PENYAKIT : ' + str(cf_penyakit))
    print('CF LABELED PENYAKIT : ' + str(cf_labeled_penyakit))


    cf_rule_unmerged = get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4)

    grouped_cf_rule = group_cf_rules(get_cf_rules(rule, jawaban_pasien, penyakit,
                                  cf_penyakit, penghubung_rule, 4))
    
    print('CF UNMERGED RULE : ' + str(cf_rule_unmerged))
    print('CF GROUPED RULE : ' + str(grouped_cf_rule))


    cf_rule_merged = merge_labeled_cf_rules(grouped_cf_rule)

    print('CF MERGED RULE : ' + str(cf_rule_merged))

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                           1. CFRULE                                   |')
    print('+-----------------------------------------------------------------------+')

    print()    

    print_cf_penyakit(penyakit, jumlah_pasien_penderita_gejala_per_penyakit,
                 total_pasien_suatu_penyakit, digit=4)

    print()
    
    print('+-----------------------------------------------------------------------+')
    print('|                              2 . RULE                                 |')
    print('+-----------------------------------------------------------------------+')

    print_labeled_rule(rule, jawaban_pasien, cf_penyakit, penghubung_rule)

    print()

    print('+-----------------------------------------------------------------------+')
    print('|                              3 . PROSES                               |')
    print('+-----------------------------------------------------------------------+')

    print_proses(penyakit, jawaban_pasien, cf_penyakit, rule, penghubung_rule, digit=4)


    print()

    print('+-----------------------------------------------------------------------+')
    print('|                        4 . TINGKAT KEPASTIAN                          |')
    print('+-----------------------------------------------------------------------+\n\n')

    print_tingkat_kepastian(cf_rule_unmerged, digit=10000000)


if __name__ == '__main__':
    demo_8();