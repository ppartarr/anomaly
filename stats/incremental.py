import math
import numpy as np


class Statistics:
    def __init__(self, Lambda, ID, init_time=0, isTypeDiff=False):  # timestamp is creation time
        self.ID = ID
        self.CF1 = 0  # linear sum
        self.CF2 = 0  # sum of squares
        self.w = 1e-20  # weight
        self.isTypeDiff = isTypeDiff
        self.Lambda = Lambda  # Decay Factor
        self.lastTimestamp = init_time
        self.cur_mean = np.nan
        self.cur_var = np.nan
        self.cur_std = np.nan
        # a list of StatisticsCovariences (references) with relate to this
        # Statistics
        self.covs = []

    def insert(self, v, t=0):  # v is a scalar, t is v's arrival the timestamp
        if self.isTypeDiff:
            dif = t - self.lastTimestamp
            if dif > 0:
                v = dif
            else:
                v = 0
        self.process_decay(t)

        # update with v
        self.CF1 += v
        self.CF2 += math.pow(v, 2)
        self.w += 1
        self.cur_mean = np.nan  # force recalculation if called
        self.cur_var = np.nan
        self.cur_std = np.nan

        # update covs (if any)
        for cov in self.covs:
            cov.update_cov(self.ID, v, t)

    def process_decay(self, timestamp):
        factor = 1
        # check for decay
        timeDiff = timestamp - self.lastTimestamp
        if timeDiff > 0:
            factor = math.pow(2, (-self.Lambda * timeDiff))
            self.CF1 = self.CF1 * factor
            self.CF2 = self.CF2 * factor
            self.w = self.w * factor
            self.lastTimestamp = timestamp
        return factor

    def weight(self):
        return self.w

    def mean(self):
        if math.isnan(self.cur_mean):  # calculate it only once when necessary
            self.cur_mean = self.CF1 / self.w
        return self.cur_mean

    def var(self):
        if math.isnan(self.cur_var):  # calculate it only once when necessary
            self.cur_var = abs(self.CF2 / self.w - math.pow(self.mean(), 2))
        return self.cur_var

    def std(self):
        if math.isnan(self.cur_std):  # calculate it only once when necessary
            self.cur_std = math.sqrt(self.var())
        return self.cur_std

    def cov(self, ID2):
        for cov in self.covs:
            if cov.Statisticss[0].ID == ID2 or cov.Statisticss[1].ID == ID2:
                return cov.cov()
        return [np.nan]

    def pcc(self, ID2):
        for cov in self.covs:
            if cov.Statisticss[0].ID == ID2 or cov.Statisticss[1].ID == ID2:
                return cov.pcc()
        return [np.nan]

    def cov_pcc(self, ID2):
        for cov in self.covs:
            if cov.Statisticss[0].ID == ID2 or cov.Statisticss[1].ID == ID2:
                return cov.get_stats1()
        return [np.nan] * 2

    def radius(self, other_Statisticss):  # the radius of a set of Statisticss
        A = self.var()**2
        for incS in other_Statisticss:
            A += incS.var()**2
        return math.sqrt(A)

    def magnitude(self, other_Statisticss):  # the magnitude of a set of Statisticss
        A = math.pow(self.mean(), 2)
        for incS in other_Statisticss:
            A += math.pow(incS.mean(), 2)
        return math.sqrt(A)

    # calculates and pulls all stats on this stream
    def allstats_1D(self):
        self.cur_mean = self.CF1 / self.w
        self.cur_var = abs(self.CF2 / self.w - math.pow(self.cur_mean, 2))
        return [self.w, self.cur_mean, self.cur_var]

    # calculates and pulls all stats on this stream, and stats shared with the
    # indicated stream
    def allstats_2D(self, ID2):
        stats1D = self.allstats_1D()
        # Find cov component
        stats2D = [np.nan] * 4
        for cov in self.covs:
            if cov.Statisticss[0].ID == ID2 or cov.Statisticss[1].ID == ID2:
                stats2D = cov.get_stats2()
                break
        return stats1D + stats2D

    def get_headers_1D(self, suffix=True):
        if self.ID is None:
            s0 = ""
        else:
            s0 = "_0"
        if suffix:
            s0 = "_" + self.ID
        headers = ["weight" + s0, "mean" + s0, "std" + s0]
        return headers

    def get_headers_2D(self, ID2, suffix=True):
        hdrs1D = self.get_headers_1D(suffix)
        if self.ID is None:
            s0 = ""
            s1 = ""
        else:
            s0 = "_0"
            s1 = "_1"
        if suffix:
            s0 = "_" + self.ID
            s1 = "_" + ID2
        hdrs2D = [
            "radius_" + s0 + "_" + s1,
            "magnitude_" + s0 + "_" + s1,
            "covariance_" + s0 + "_" + s1,
            "pcc_" + s0 + "_" + s1]
        return hdrs1D + hdrs2D


class StatisticsCovarience:
    """Similar to Statistics, but maintains stats between two streams"""

    def __init__(self, incS1, incS2, init_time=0):
        # store references to the streams' Statisticss
        self.Statisticss = [incS1, incS2]
        self.lastRes = [0, 0]
        # init extrapolators
        #self.EXs = [extrapolator(),extrapolator()]

        # init sum product residuals
        self.CF3 = 0  # sum of residule products (A-uA)(B-uB)
        self.w3 = 1e-20
        self.lastTimestamp_cf3 = init_time

    # other_incS_decay is the decay factor of the other incstat
    # ID: the stream ID which produced (v,t)
    # it is assumes that Statistics "ID" has ALREADY been updated with (t,v)
    # [this si performed automatically in method Statistics.insert()]
    def update_cov(self, ID, v, t):
        # find Statistics
        if ID == self.Statisticss[0].ID:
            inc = 0
        elif ID == self.Statisticss[1].ID:
            inc = 1
        else:
            print("update_cov ID error")
            return  # error

        # Decay other Statistics
        self.Statisticss[not(inc)].process_decay(t)

        # Decay residules
        self.process_decay(t, inc)

        # Update extrapolator for current stream
        # self.EXs[inc].insert(t,v)

        # Extrapolate other stream
        #v_other = self.EXs[not(inc)].predict(t)

        # Compute and update residule
        res = (v - self.Statisticss[inc].mean())
        resid = (v - self.Statisticss[inc].mean()) * self.lastRes[not(inc)]
        self.CF3 += resid
        self.w3 += 1
        self.lastRes[inc] = res

    def process_decay(self, t, micro_inc_indx):
        factor = 1
        # check for decay cf3
        timeDiffs_cf3 = t - self.lastTimestamp_cf3
        if timeDiffs_cf3 > 0:
            factor = math.pow(
                2, (-(self.Statisticss[micro_inc_indx].Lambda) * timeDiffs_cf3))
            self.CF3 *= factor
            self.w3 *= factor
            self.lastTimestamp_cf3 = t
            self.lastRes[micro_inc_indx] *= factor
        return factor

    # todo: add W3 for cf3

    # covariance approximation
    def cov(self):
        return self.CF3 / self.w3

    # Pearson corl. coef
    def pcc(self):
        ss = self.Statisticss[0].std() * self.Statisticss[1].std()
        if ss != 0:
            return self.cov() / ss
        else:
            return 0

    # calculates and pulls all correlative stats
    def get_stats1(self):
        return [self.cov(), self.pcc()]

    # calculates and pulls all correlative stats AND 2D stats from both
    # streams (Statistics)
    def get_stats2(self):
        return [self.Statisticss[0].radius([self.Statisticss[1]]), self.Statisticss[0].magnitude([
            self.Statisticss[1]]), self.cov(), self.pcc()]

    # calculates and pulls all correlative stats AND 2D stats AND the regular
    # stats from both streams (Statistics)
    def get_stats3(self):
        return [
            self.Statisticss[0].w,
            self.Statisticss[0].mean(),
            self.Statisticss[0].std(),
            self.Statisticss[1].w,
            self.Statisticss[1].mean(),
            self.Statisticss[1].std(),
            self.cov(),
            self.pcc()]

    # calculates and pulls all correlative stats AND the regular stats from
    # both Statisticss AND 2D stats
    def get_stats4(self):
        return [self.Statisticss[0].w,
                self.Statisticss[0].mean(),
                self.Statisticss[0].std(),
                self.Statisticss[1].w,
                self.Statisticss[1].mean(),
                self.Statisticss[1].std(),
                self.Statisticss[0].radius([self.Statisticss[1]]),
                self.Statisticss[0].magnitude([self.Statisticss[1]]),
                self.cov(),
                self.pcc()]

    def get_headers(self, ver, suffix=True):  # ver = {1,2,3,4}
        headers = []
        s0 = "0"
        s1 = "1"
        if suffix:
            s0 = self.Statisticss[0].ID
            s1 = self.Statisticss[1].ID

        if ver == 1:
            headers = ["covariance_" + s0 + "_" + s1, "pcc_" + s0 + "_" + s1]
        if ver == 2:
            headers = [
                "radius_" + s0 + "_" + s1,
                "magnitude_" + s0 + "_" + s1,
                "covariance_" + s0 + "_" + s1,
                "pcc_" + s0 + "_" + s1]
        if ver == 3:
            headers = [
                "weight_" + s0,
                "mean_" + s0,
                "std_" + s0,
                "weight_" + s1,
                "mean_" + s1,
                "std_" + s1,
                "covariance_" + s0 + "_" + s1,
                "pcc_" + s0 + "_" + s1]
        if ver == 4:
            headers = [
                "weight_" + s0,
                "mean_" + s0,
                "std_" + s0,
                "covariance_" + s0 + "_" + s1,
                "pcc_" + s0 + "_" + s1]
        if ver == 5:
            headers = [
                "weight_" + s0,
                "mean_" + s0,
                "std_" + s0,
                "weight_" + s1,
                "mean_" + s1,
                "std_" + s1,
                "radius_" + s0 + "_" + s1,
                "magnitude_" + s0 + "_" + s1,
                "covariance_" + s0 + "_" + s1,
                "pcc_" + s0 + "_" + s1]
        return headers


class StatisticsDB:
    # default_Lambda: use this as the Lambda for all streams. If not
    # specified, then you must supply a Lambda with every query.
    def __init__(self, limit=np.Inf, default_Lambda=np.nan):
        self.HT = dict()
        self.limit = limit
        self.df_Lambda = default_Lambda

    def get_Lambda(self, Lambda):
        if not np.isnan(self.df_Lambda):
            Lambda = self.df_Lambda
        return Lambda

    # Registers a new stream. init_time: init lastTimestamp of the Statistics
    def register(self, ID, Lambda=1, init_time=0, isTypeDiff=False):
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)

        # Retrieve Statistics
        key = str(ID) + "_" + str(Lambda)
        incS = self.HT.get(key)
        if incS is None:  # does not already exist
            if len(self.HT) + 1 > self.limit:
                raise LookupError('Adding Entry:\n' +
                                  key +
                                  '\nwould exceed StatisticsHT 1D limit of ' +
                                  str(self.limit) +
                                  '.\nObservation Rejected.')
            incS = Statistics(Lambda, ID, init_time, isTypeDiff)
            self.HT[key] = incS  # add new entry
        return incS

    # Registers covariance tracking for two streams, registers missing streams
    def register_cov(self, ID1, ID2, Lambda=1, init_time=0, isTypeDiff=False):
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)

        # Lookup both streams
        incS1 = self.register(ID1, Lambda, init_time, isTypeDiff)
        incS2 = self.register(ID2, Lambda, init_time, isTypeDiff)

        # check for pre-exiting link
        for cov in incS1.covs:
            if cov.Statisticss[0].ID == ID2 or cov.Statisticss[1].ID == ID2:
                return cov  # there is a pre-exiting link

        # Link Statisticss
        inc_cov = StatisticsCovarience(incS1, incS2, init_time)
        incS1.covs.append(inc_cov)
        incS2.covs.append(inc_cov)
        return inc_cov

    # updates/registers stream
    def update(self, ID, t, v, Lambda=1, isTypeDiff=False):
        incS = self.register(ID, Lambda, t, isTypeDiff)
        incS.insert(v, t)
        return incS

    # Pulls current stats from the given ID
    def get_1D_stats(self, ID, Lambda=1):  # weight, mean, std
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)

        # Get Statistics
        incS = self.HT.get(ID + "_" + str(Lambda))
        if incS is None:  # does not already exist
            return [np.na] * 3
        else:
            return incS.allstats_1D()

    # Pulls current correlational stats from the given IDs
    def get_2D_stats(self, ID1, ID2, Lambda=1):  # cov, pcc
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)

        # Get Statistics
        incS1 = self.HT.get(ID1 + "_" + str(Lambda))
        if incS1 is None:  # does not exist
            return [np.na] * 2

        # find relevant cov entry
        return incS1.cov_pcc(ID2)

    # Pulls all correlational stats registered with the given ID
    # returns tuple [0]: stats-covs&pccs, [2]: IDs
    def get_all_2D_stats(self, ID, Lambda=1):  # cov, pcc
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)

        # Get Statistics
        incS1 = self.HT.get(ID + "_" + str(Lambda))
        if incS1 is None:  # does not exist
            return ([], [])

        # find relevant cov entry
        stats = []
        IDs = []
        for cov in incS1.covs:
            stats.append(cov.get_stats1())
            IDs.append([cov.Statisticss[0].ID, cov.Statisticss[1].ID])
        return stats, IDs

    # Pulls current multidimensional stats from the given IDs
    def get_nD_stats(self, IDs, Lambda=1):  # radius, magnitude (IDs is a list)
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)

        # Get Statisticss
        Statisticss = []
        for ID in IDs:
            incS = self.HT.get(ID + "_" + str(Lambda))
            if incS is not None:  # exists
                Statisticss.append(incS)

        # Compute stats
        rad = 0  # radius
        mag = 0  # magnitude
        for incS in Statisticss:
            rad += incS.var()
            mag += incS.mean()**2

        return [np.sqrt(rad), np.sqrt(mag)]

    # Updates and then pulls current 1D stats from the given ID. Automatically
    # registers previously unknown stream IDs
    def update_get_1D_stats(self, ID, t, v, Lambda=1, isTypeDiff=False):  # weight, mean, std
        incS = self.update(ID, t, v, Lambda, isTypeDiff)
        return incS.allstats_1D()

    # Updates and then pulls current correlative stats between the given IDs. Automatically registers previously unknown stream IDs, and cov tracking
    # Note: AfterImage does not currently support Diff Type streams for
    # correlational statistics.
    # level=  1:cov,pcc  2:radius,magnitude,cov,pcc
    def update_get_2D_stats(self, ID1, ID2, t1, v1, Lambda=1, level=1):
        # retrieve/add cov tracker
        inc_cov = self.register_cov(ID1, ID2, Lambda, t1)
        # Update cov tracker
        inc_cov.update_cov(ID1, v1, t1)
        if level == 1:
            return inc_cov.get_stats1()
        else:
            return inc_cov.get_stats2()

    # Updates and then pulls current 1D and 2D stats from the given IDs.
    # Automatically registers previously unknown stream IDs
    def update_get_1D2D_stats(self, ID1, ID2, t1, v1, Lambda=1):  # weight, mean, std
        return self.update_get_1D_stats(ID1,
                                        t1,
                                        v1,
                                        Lambda) + self.update_get_2D_stats(ID1,
                                                                           ID2,
                                                                           t1,
                                                                           v1,
                                                                           Lambda,
                                                                           level=2)

    def get_headers_1D(self, Lambda=1, ID=None):
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)
        hdrs = Statistics(Lambda, ID).get_headers_1D(suffix=False)
        return [str(Lambda) + "_" + s for s in hdrs]

    def get_headers_2D(self, Lambda=1, IDs=None, ver=1):  # IDs is a 2-element list or tuple
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)
        if IDs is None:
            IDs = [0, 1]
        hdrs = StatisticsCovarience(
            Statistics(
                Lambda, IDs[0]), Statistics(
                Lambda, IDs[0]), Lambda).get_headers(
            ver, suffix=False)
        return [str(Lambda) + "_" + s for s in hdrs]

    def get_headers_1D2D(self, Lambda=1, IDs=None, ver=1):
        # Default Lambda?
        Lambda = self.get_Lambda(Lambda)
        if IDs is None:
            IDs = [0, 1]
        hdrs1D = self.get_headers_1D(Lambda, IDs[0])
        hdrs2D = self.get_headers_2D(Lambda, IDs, ver)
        return hdrs1D + hdrs2D

    def get_headers_nD(self, Lambda=1, IDs=[]):  # IDs is a n-element list or tuple
        # Default Lambda?
        ID = ":"
        for s in IDs:
            ID += "_" + s
        Lambda = self.get_Lambda(Lambda)
        hdrs = ["radius" + ID, "magnitude" + ID]
        return [str(Lambda) + "_" + s for s in hdrs]

    # cleans out records that have a weight less than the cutoff.
    # returns number or removed records.

    def clean_old_records(self, cutoffWeight, curTime):
        n = 0
        dump = sorted(
            self.HT.items(),
            key=lambda tup: tup[1][0].getMaxW(curTime))
        for entry in dump:
            entry[1][0].process_decay(curTime)
            W = entry[1][0].w
            if W <= cutoffWeight:
                key = entry[0]
                del entry[1][0]
                del self.HT[key]
                n = n + 1
            elif W > cutoffWeight:
                break
        return n
